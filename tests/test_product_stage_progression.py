"""Unit tests for Product-Level Analysis Progression and Integrity Rules."""

from pathlib import Path
import re
import unittest


class TestProductStageProgression(unittest.TestCase):
    """Verifies that dashboard HTML defines the 5-stage product progression

    and follows the critical integrity rules for analysis stages.
    """

    @classmethod
    def setUpClass(cls):
        template_path = Path(__file__).resolve().parent.parent / "src" / "templates" / "dashboard.html"
        cls.html = template_path.read_text(encoding="utf-8")

    def test_product_stages_present_in_dashboard_html(self):
        """Primary UI must expose the 5 product-level stages."""
        self.assertIn("1. Application Acquisition", self.html)
        self.assertIn("2. Static Analysis", self.html)
        self.assertIn("3. Dynamic Analysis", self.html)
        self.assertIn("4. Agent Analysis", self.html)
        self.assertIn("5. Report Generation", self.html)

        # Stage card and badge IDs
        self.assertIn('id="card-app_acquisition"', self.html)
        self.assertIn('id="card-static_analysis"', self.html)
        self.assertIn('id="card-dynamic_analysis"', self.html)
        self.assertIn('id="card-agent_analysis"', self.html)
        self.assertIn('id="card-report_generation"', self.html)

        self.assertIn('id="badge-app_acquisition"', self.html)
        self.assertIn('id="badge-static_analysis"', self.html)
        self.assertIn('id="badge-dynamic_analysis"', self.html)
        self.assertIn('id="badge-agent_analysis"', self.html)
        self.assertIn('id="badge-report_generation"', self.html)

    def test_internal_developer_stage_titles_removed_from_primary_progression(self):
        """Developer console stage titles must not appear as primary progression titles."""
        self.assertNotIn("1. Acquisition", self.html)
        self.assertNotIn("2. Preprocessing", self.html)
        self.assertNotIn("4. Runtime Launch Verification", self.html)

    def test_derive_product_stages_helper_present_in_script(self):
        """Centralized stage adapter deriveProductStages must exist in script."""
        self.assertIn("function deriveProductStages(backendStages, statusData)", self.html)

    def test_critical_integrity_rules_in_adapter_logic(self):
        """Verifies that the script strictly implements the 3 critical integrity rules."""
        # 1. runtime launch success != Dynamic Analysis completed
        # Dynamic analysis must never be marked 'completed' from runtime stage
        self.assertIn('product.dynamic_analysis.state = "not_available"', self.html)
        # Ensure 'product.dynamic_analysis.state = "completed"' is NOT present anywhere
        self.assertNotIn('product.dynamic_analysis.state = "completed"', self.html)

        # 2. agent backend absent != Agent Analysis completed
        # Agent analysis must never be marked 'running' or 'completed'
        self.assertNotIn('product.agent_analysis.state = "running"', self.html)
        self.assertNotIn('product.agent_analysis.state = "completed"', self.html)

        # 3. static report exists != Full Report Generation completed
        # Report generation must never be marked 'completed' solely on static report
        self.assertNotIn('product.report_generation.state = "completed"', self.html)

    def test_product_state_vocabulary_in_badge_handler(self):
        """Badges and cards must normalize to the product vocabulary."""
        self.assertIn('"Pending"', self.html)
        self.assertIn('"Running"', self.html)
        self.assertIn('"Completed"', self.html)
        self.assertIn('"Partial"', self.html)
        self.assertIn('"Failed"', self.html)
        self.assertIn('"Not Available"', self.html)


if __name__ == "__main__":
    unittest.main()
