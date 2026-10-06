import pytest
import numpy as np
import tempfile
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.ml.detector import NightOwlAnomalyDetector
from sklearn.covariance import LedoitWolf

def test_detector_initialization():
    detector = NightOwlAnomalyDetector()
    assert isinstance(detector.model, LedoitWolf)
    assert not detector.is_trained
    assert detector.threshold_suspicious is None
    assert detector.threshold_high is None

def test_detector_training():
    detector = NightOwlAnomalyDetector()
    
    # Create some dummy features (e.g. 100 windows, 70 features)
    # Give them some non-zero values to avoid singular covariance if log1p was skipped, 
    # but LedoitWolf handles zero variance perfectly anyway.
    np.random.seed(42)
    X = np.random.uniform(0, 10, size=(100, 70))
    
    detector.train(X)
    
    assert detector.is_trained
    assert detector.threshold_suspicious is not None
    assert detector.threshold_high is not None
    assert detector.threshold_high >= detector.threshold_suspicious

def test_detector_save_load():
    detector = NightOwlAnomalyDetector()
    np.random.seed(42)
    X = np.random.uniform(0, 10, size=(100, 70))
    detector.train(X)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "model.joblib")
        detector.save(model_path)
        
        assert os.path.exists(model_path)
        
        # Create a new detector and load the model
        new_detector = NightOwlAnomalyDetector()
        new_detector.load(model_path)
        
        assert new_detector.is_trained
        assert new_detector.threshold_suspicious == detector.threshold_suspicious
        assert new_detector.threshold_high == detector.threshold_high

def test_detector_scoring():
    detector = NightOwlAnomalyDetector()
    np.random.seed(42)
    # Training data (mostly small values)
    X_train = np.random.uniform(0, 2, size=(100, 70))
    detector.train(X_train)
    
    # Test data (one normal, one extremely anomalous)
    X_test = np.vstack([
        X_train[0],  # Normal
        np.array([100.0] * 70)  # Anomalous
    ])
    
    results = detector.score_window(X_test)
    
    assert len(results) == 2
    
    # The first one should be Low or Medium (since it's from training set, likely Low)
    assert results[0]['severity'] in ['Low', 'Medium']
    
    # The second one must be High
    assert results[1]['severity'] == 'High'
    assert results[1]['anomaly_score'] >= 0.68
    
    # Ensure all results contain raw_distance
    assert 'raw_distance' in results[0]
    assert 'raw_distance' in results[1]

if __name__ == "__main__":
    test_detector_initialization()
    test_detector_training()
    test_detector_save_load()
    test_detector_scoring()
    print("All tests passed.")
