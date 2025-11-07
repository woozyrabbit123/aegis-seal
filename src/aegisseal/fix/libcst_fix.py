"""LibCST-based auto-fix for secrets in Python code."""

import difflib
import re
import shutil
from pathlib import Path
from typing import List, Optional, Tuple

import libcst as cst
from libcst import matchers as m

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

    def leave_SimpleString(
        self, original_node: cst.SimpleString, updated_node: cst.SimpleString
    ) -> cst.BaseExpression:
        """Replace string literals that contain secrets."""
        # Get the position of this node
        pos = self.get_metadata(cst.metadata.PositionProvider, original_node)
        if pos is None:
            return updated_node

        line_number = pos.start.line

        # Check if this line has a finding
        if line_number not in self.findings_by_line:
            return updated_node

        finding = self.findings_by_line[line_number]

        # Check if the string contains the matched secret
        string_value = original_node.value
        if finding.matched_string not in string_value:
            return updated_node

        # Generate a sensible environment variable name
        env_var_name = self._generate_env_var_name(finding)

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

    def leave_ConcatenatedString(
        self, original_node: cst.ConcatenatedString, updated_node: cst.ConcatenatedString
    ) -> cst.BaseExpression:
        """Handle concatenated strings (e.g., f-strings)."""
        # For simplicity, we'll skip f-strings for now
        # Could be enhanced to handle them more gracefully
        return updated_node

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


def add_os_import(tree: cst.Module) -> cst.Module:
    """
    Add 'import os' to the module if not already present.

    Args:
        tree: CST module

    Returns:
        Modified module with import added
    """
    # Check if os is already imported
    has_os_import = False

    for statement in tree.body:
        if m.matches(
            statement,
            m.SimpleStatementLine(
                body=[m.Import(names=[m.AtLeastN([m.ImportAlias(name=m.Name("os"))], n=1)])]
            ),
        ):
            has_os_import = True
            break

        if m.matches(
            statement,
            m.SimpleStatementLine(
                body=[
                    m.ImportFrom(
                        module=m.Name("os"),
                    )
                ]
            ),
        ):
            has_os_import = True
            break

    if has_os_import:
        return tree

    # Add import at the top (after any docstrings)
    import_statement = cst.SimpleStatementLine(
        body=[cst.Import(names=[cst.ImportAlias(name=cst.Name("os"))])]
    )

    # Find the insertion point (after module docstring if present)
    insertion_index = 0
    if tree.body and isinstance(tree.body[0], cst.SimpleStatementLine):
        first_stmt = tree.body[0]
        if (
            first_stmt.body
            and isinstance(first_stmt.body[0], cst.Expr)
            and isinstance(first_stmt.body[0].value, cst.SimpleString)
        ):
            insertion_index = 1

    new_body = list(tree.body)
    new_body.insert(insertion_index, import_statement)

    return tree.with_changes(body=new_body)


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

        # Add os import if needed
        if replacer.needs_os_import:
            new_tree = add_os_import(new_tree)

        # Generate new code
        new_code = new_tree.code

        # Generate diff
        diff = difflib.unified_diff(
            source_code.splitlines(keepends=True),
            new_code.splitlines(keepends=True),
            fromfile=str(file_path),
            tofile=str(file_path),
            lineterm="",
        )
        diff_text = "".join(diff)

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
