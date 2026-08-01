"""
Basic unit tests for HeaderX's header-grading logic.

Run with:
    python3 -m unittest discover -s tests
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import headerx  # noqa: E402


class TestCSPGrading(unittest.TestCase):

    def test_missing_csp(self):
        check = headerx.check_csp(None)
        self.assertFalse(check.present)
        self.assertEqual(check.grade_points, 0)

    def test_strict_csp(self):
        check = headerx.check_csp("default-src 'self'; frame-ancestors 'none'")
        self.assertTrue(check.present)
        self.assertEqual(check.grade_points, check.max_points)

    def test_unsafe_csp_penalized(self):
        check = headerx.check_csp("default-src 'self' 'unsafe-inline' 'unsafe-eval'")
        self.assertTrue(check.present)
        self.assertLess(check.grade_points, check.max_points)


class TestHSTSGrading(unittest.TestCase):

    def test_missing_hsts(self):
        check = headerx.check_hsts(None)
        self.assertEqual(check.grade_points, 0)

    def test_strong_hsts(self):
        check = headerx.check_hsts("max-age=31536000; includeSubDomains; preload")
        self.assertEqual(check.grade_points, check.max_points)

    def test_weak_max_age_penalized(self):
        check = headerx.check_hsts("max-age=60")
        self.assertLess(check.grade_points, check.max_points)


class TestCookieGrading(unittest.TestCase):

    def test_no_cookies(self):
        check = headerx.check_cookies([])
        self.assertEqual(check.grade_points, headerx.COOKIE_MAX_POINTS)

    def test_fully_flagged_cookie(self):
        check = headerx.check_cookies(["session=abc; Secure; HttpOnly; SameSite=Strict"])
        self.assertEqual(check.grade_points, headerx.COOKIE_MAX_POINTS)

    def test_unflagged_cookie_penalized(self):
        check = headerx.check_cookies(["session=abc;"])
        self.assertEqual(check.grade_points, 0)


class TestDisclosure(unittest.TestCase):

    def test_no_disclosure(self):
        check = headerx.check_disclosure({})
        self.assertEqual(check.grade_points, headerx.DISCLOSURE_MAX_POINTS)

    def test_disclosure_penalized(self):
        check = headerx.check_disclosure({"Server": "Apache/2.4", "X-Powered-By": "PHP/7.4"})
        self.assertLess(check.grade_points, headerx.DISCLOSURE_MAX_POINTS)


class TestGradeFromScore(unittest.TestCase):

    def test_grade_boundaries(self):
        self.assertEqual(headerx.grade_from_score(100), "A+")
        self.assertEqual(headerx.grade_from_score(90), "A")
        self.assertEqual(headerx.grade_from_score(75), "B")
        self.assertEqual(headerx.grade_from_score(60), "C")
        self.assertEqual(headerx.grade_from_score(45), "D")
        self.assertEqual(headerx.grade_from_score(10), "F")


if __name__ == "__main__":
    unittest.main()
