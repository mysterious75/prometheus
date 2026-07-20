"""Code Generator - AI-powered code generation."""

from typing import Dict, Any, Optional
from datetime import datetime

from ..brain.router import ModelRouter
from ..utils.logger import logger


class CodeGenerator:
    """AI-powered code generation system."""

    def __init__(self, router: ModelRouter):
        self.router = router
        self.generated_code: list = []

    def generate_code(self, description: str, language: str = "python") -> str:
        """Generate code from description."""
        logger.info(f"[*] Generating {language} code: {description[:50]}...")

        prompt = f"""
        Generate {language} code for the following requirement:

        {description}

        Requirements:
        - Clean, well-commented code
        - Follow best practices
        - Include error handling
        - Add docstrings

        Return ONLY the code, no explanations.
        """

        code = self.router.generate(prompt)

        self.generated_code.append({
            "description": description,
            "language": language,
            "code": code,
            "timestamp": datetime.now().isoformat()
        })

        return code

    def review_code(self, code: str) -> Dict[str, Any]:
        """Review code for issues."""
        prompt = f"""
        Review the following code for:
        1. Bugs or errors
        2. Security issues
        3. Performance problems
        4. Best practices violations
        5. Suggestions for improvement

        Code:
        {code}

        Provide a structured review.
        """

        review = self.router.generate(prompt)

        return {
            "code": code[:100] + "...",
            "review": review,
            "timestamp": datetime.now().isoformat()
        }

    def refactor_code(self, code: str, instruction: str) -> str:
        """Refactor code based on instruction."""
        prompt = f"""
        Refactor the following code:

        Original Code:
        {code}

        Instruction: {instruction}

        Return the refactored code.
        """

        return self.router.generate(prompt)
