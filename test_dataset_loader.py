import unittest

from dataset_loader import DatasetLoader


class TestDatasetLoader(unittest.TestCase):

    def setUp(self):
        self.loader = DatasetLoader()

    def test_load_dataset(self):
        self.assertEqual(len(self.loader.get_all_cases()), 55)

    def test_get_case(self):
        case = self.loader.get_case("CASE-001")

        self.assertEqual(case["case_id"], "CASE-001")

    def test_invalid_case(self):
        with self.assertRaises(KeyError):
            self.loader.get_case("INVALID")

    def test_filter_category(self):
        cases = self.loader.get_cases_by_category("valid_small")

        self.assertEqual(len(cases), 10)

        for case in cases:
            self.assertEqual(case["category"], "valid_small")

    def test_category_counts(self):
        counts = self.loader.get_category_counts()

        expected = {
            "valid_small": 10,
            "valid_large": 15,
            "trap_non_coprime": 10,
            "trap_different_messages": 10,
            "trap_broken_setup": 10
        }

        self.assertEqual(counts, expected)

    def test_public_parameters(self):
        parameters = self.loader.get_public_parameters("CASE-001")

        expected_fields = {
            "n1", "n2", "e1", "e2", "c1", "c2"
        }

        self.assertEqual(set(parameters.keys()), expected_fields)


if __name__ == "__main__":
    unittest.main()