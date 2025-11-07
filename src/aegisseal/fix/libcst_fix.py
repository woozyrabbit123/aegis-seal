"""LibCST-based auto-fix for secrets in Python code."""

import difflib
import re
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import libcst as cst
from libcst import matchers as m
from libcst.codemod import CodemodContext, VisitorBasedCodemodCommand
from libcst.codemod.visitors import AddImportsVisitor

from aegisseal.scanning.detectors import Finding


class SecretReplacer(cst.CSTTransformer):
    """LibCST transformer to replace hardcoded secrets with os.getenv()."""

    METADATA_DEPENDENCIES = (cst.metadata.PositionProvider,)

    def __init__(self, findings: List[Finding], file_path: str):
        """
        Initialize the transformer.

        Args:
            findings: List of findings for this file
            file_path: Path to the file being transformed
        """
        super().__init__()
        self.findings = findings
        self.file_path = file_path
        self.replacements_made = 0
        self.needs_os_import = False

        # Build a map of line numbers to findings
        # Note: We accept all findings since caller should filter by file
        self.findings_by_line = {}
        for finding in findings:
            self.findings_by_line[finding.line_number] = finding

        # Map secret values to env var names for consistency
        # This ensures repeated secrets use the same env var name
        self.secret_to_env_var: Dict[str, str] = {}

    def leave_SimpleString(
        self, original_node: cst.SimpleString, updated_node: cst.SimpleString
    ) -> cst.BaseExpression:
        """Replace string literals that contain secrets."""
        # Get the position of this node
        pos = self.get_metadata(cst.metadata.PositionProvider, original_node)
        if pos is None:
            return updated_node

        line_number = pos.start.line
        string_value = original_node.value

        # Check if this line has a finding
        finding = None
        if line_number in self.findings_by_line:
            finding = self.findings_by_line[line_number]
            # Verify the string contains the matched secret
            if finding.matched_string not in string_value:
                finding = None

        # For multiline strings, also check if any finding's secret is in this string
        # This handles cases where the finding line is within a multiline string
        if finding is None:
            for f in self.findings:
                if f.matched_string in string_value:
                    # Verify this finding overlaps with this string's position
                    if pos.start.line <= f.line_number <= pos.end.line:
                        finding = f
                        break

        if finding is None:
            return updated_node

        # Generate a sensible environment variable name (with caching for repeated secrets)
        env_var_name = self._get_or_create_env_var_name(finding)

        # Create os.getenv() call
        self.needs_os_import = True
        self.replacements_made += 1

        # Build: os.getenv("VAR_NAME")
        getenv_call = cst.Call(
            func=cst.Attribute(
                value=cst.Name("os"),
                attr=cst.Name("getenv"),
            ),
            args=[cst.Arg(cst.SimpleString(f'"{env_var_name}"'))],
        )

        return getenv_call

    def leave_FormattedString(
        self, original_node: cst.FormattedString, updated_node: cst.FormattedString
    ) -> cst.BaseExpression:
        """Handle f-strings by replacing only literal segments."""
        pos = self.get_metadata(cst.metadata.PositionProvider, original_node)
        if pos is None:
            return updated_node

        line_number = pos.start.line

        # Check if this line has a finding
        if line_number not in self.findings_by_line:
            return updated_node

        finding = self.findings_by_line[line_number]

        # Search for the secret in the literal parts of the f-string
        new_parts = []
        modified = False

        for part in updated_node.parts:
            if isinstance(part, cst.FormattedStringText):
                # Check if this literal segment contains the secret
                if finding.matched_string in part.value:
                    # Replace the literal with an expression that calls os.getenv()
                    env_var_name = self._get_or_create_env_var_name(finding)
                    self.needs_os_import = True
                    self.replacements_made += 1
                    modified = True

                    # Create os.getenv('VAR_NAME') as a formatted expression
                    # Use single quotes to avoid conflicts with f-string double quotes
                    getenv_expr = cst.FormattedStringExpression(
                        expression=cst.Call(
                            func=cst.Attribute(
                                value=cst.Name("os"),
                                attr=cst.Name("getenv"),
                            ),
                            args=[cst.Arg(cst.SimpleString(f"'{env_var_name}'"))],
                        )
                    )
                    new_parts.append(getenv_expr)
                else:
                    new_parts.append(part)
            else:
                # Keep expressions as-is
                new_parts.append(part)

        if modified:
            return updated_node.with_changes(parts=new_parts)

        return updated_node

    def leave_ConcatenatedString(
        self, original_node: cst.ConcatenatedString, updated_node: cst.ConcatenatedString
    ) -> cst.BaseExpression:
        """Handle concatenated strings (implicit string concatenation)."""
        # ConcatenatedString is for implicit concatenation like "a" "b"
        # FormattedString handles f-strings
        # For now, we'll let the child nodes handle their own replacements
        return updated_node

    def _get_or_create_env_var_name(self, finding: Finding) -> str:
        """
        Get or create an environment variable name for a secret.

        Uses caching to ensure repeated secrets get the same env var name.

        Args:
            finding: The finding

        Returns:
            Environment variable name
        """
        secret_key = finding.matched_string

        if secret_key not in self.secret_to_env_var:
            self.secret_to_env_var[secret_key] = self._generate_env_var_name(finding)

        return self.secret_to_env_var[secret_key]

    @staticmethod
    def _generate_env_var_name(finding: Finding) -> str:
        """
        Generate a sensible environment variable name.

        Args:
            finding: The finding

        Returns:
            Environment variable name
        """
        # Try to infer from rule name
        rule_name = finding.rule_name.upper().replace(" ", "_")

        # Common mappings
        mappings = {
            "GITHUB_PERSONAL_ACCESS_TOKEN": "GITHUB_TOKEN",
            "GITHUB_OAUTH_ACCESS_TOKEN": "GITHUB_OAUTH_TOKEN",
            "AWS_ACCESS_KEY_ID": "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY": "AWS_SECRET_ACCESS_KEY",
            "SLACK_TOKEN": "SLACK_TOKEN",
            "STRIPE_API_KEY": "STRIPE_API_KEY",
            "GOOGLE_API_KEY": "GOOGLE_API_KEY",
        }

        # Check if we have a mapping
        for key, value in mappings.items():
            if key in rule_name:
                return value

        # Fallback: use a generic name based on rule
        return "SECRET_VALUE"


def add_os_import_idempotent(tree: cst.Module, context: CodemodContext) -> cst.Module:
    """
    Add 'import os' to the module using AddImportsVisitor for idempotency.

    This ensures we don't add duplicate imports if os is already imported.

    Args:
        tree: CST module
        context: Codemod context

    Returns:
        Modified module with import added
    """
    # Use AddImportsVisitor for idempotent import addition
    AddImportsVisitor.add_needed_import(context, "os")
    return tree


def apply_fixes(
    file_path: Path,
    findings: List[Finding],
    dry_run: bool = True,
) -> Tuple[bool, Optional[str]]:
    """
    Apply fixes to a Python file.

    Args:
        file_path: Path to the file
        findings: List of findings for this file
        dry_run: If True, only generate diff without applying

    Returns:
        Tuple of (success, diff_or_error)
    """
    try:
        # Read the file
        with open(file_path, "r", encoding="utf-8") as f:
            source_code = f.read()

        # Parse with LibCST
        try:
            tree = cst.parse_module(source_code)
        except cst.ParserSyntaxError as e:
            return False, f"Syntax error: {e}"

        # Set up metadata
        metadata_wrapper = cst.MetadataWrapper(tree)

        # Apply replacements
        replacer = SecretReplacer(findings, str(file_path))
        new_tree = metadata_wrapper.visit(replacer)

        if replacer.replacements_made == 0:
            return True, "No replacements made (no matching string literals found)"

        # Add os import if needed (idempotently)
        if replacer.needs_os_import:
            # Create a codemod context for AddImportsVisitor
            context = CodemodContext()
            new_tree = add_os_import_idempotent(new_tree, context)

            # Apply the import additions
            new_tree = new_tree.visit(AddImportsVisitor(context))

        # Generate new code
        new_code = new_tree.code

        # Generate diff with stable ordering
        # Sort lines to ensure deterministic output
        diff_lines = list(difflib.unified_diff(
            source_code.splitlines(keepends=True),
            new_code.splitlines(keepends=True),
            fromfile=str(file_path),
            tofile=str(file_path),
            lineterm="",
        ))

        # Diff is already in line order, so it's naturally stable
        diff_text = "".join(diff_lines)

        if not dry_run:
            # Create backup
            backup_path = file_path.with_suffix(file_path.suffix + ".bak")
            shutil.copy2(file_path, backup_path)

            # Write the fixed file
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(new_code)

            return True, f"Applied {replacer.replacements_made} fix(es). Backup saved to {backup_path}"

        return True, diff_text

    except Exception as e:
        return False, f"Error processing file: {e}"


def filter_python_findings(findings: List[Finding]) -> List[Finding]:
    """
    Filter findings to only include Python files.

    Args:
        findings: List of all findings

    Returns:
        List of findings from Python files
    """
    return [f for f in findings if f.file_path.endswith(".py")]
