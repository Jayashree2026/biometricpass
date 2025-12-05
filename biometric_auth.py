import cv2
import numpy as np
import base64
import time   
from PyQt5.QtWidgets import QMessageBox
from facenet_pytorch import MTCNN, InceptionResnetV1


class BiometricAuthenticator:
    def __init__(self, parent, db_manager):
        self.parent = parent
        self.db = db_manager

        # Load face detector + embedder
        self.detector = MTCNN(keep_all=False)
        self.embedder = InceptionResnetV1(pretrained="vggface2").eval()

    # ------------------------------------------------------
    # Simple motion-based liveness detection
    # ------------------------------------------------------
    def _check_liveness_motion(self, seconds=2, threshold=300000):   # ✅ ADDED
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return False

        t_end = time.time() + seconds

        ret, prev = cap.read()
        if not ret:
            cap.release()
            return False

        prev_gray = cv2.cvtColor(prev, cv2.COLOR_BGR2GRAY)
        motion_score = 0

        while time.time() < t_end:
            ret, frame = cap.read()
            if not ret:
                break

            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            diff = cv2.absdiff(prev_gray, gray)
            motion_score += diff.sum()
            prev_gray = gray

        cap.release()
        return motion_score > threshold

    # ------------------------------------------------------
    # Capture a face image
    # ------------------------------------------------------
    def _capture_image(self):
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            QMessageBox.critical(self.parent, "Camera Error", "Could not access webcam.")
            return None

        QMessageBox.information(
            self.parent,
            "Face Capture",
            "Look at the camera. Press OK to capture your face."
        )

        ret, frame = cap.read()
        cap.release()

        if not ret:
            QMessageBox.critical(self.parent, "Capture Error", "Failed to capture frame.")
            return None

        return cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

    # ------------------------------------------------------
    # Extract Face Embedding
    # ------------------------------------------------------
    def _get_embedding(self, img):
        try:
            face = self.detector(img)
            if face is None:
                QMessageBox.warning(self.parent, "Biometric", "No face detected.")
                return None

            embedding = self.embedder(face.unsqueeze(0))
            return embedding.detach().numpy()[0]
        except Exception:
            QMessageBox.warning(self.parent, "Biometric", "Face processing failed.")
            return None

    # ------------------------------------------------------
    # Register face + liveness check
    # ------------------------------------------------------
    def register_face(self):
        # ✅ LIVENESS CHECK BEFORE CAPTURE
        QMessageBox.information(self.parent, "Liveness", "Please move your head slightly or blink.")
        if not self._check_liveness_motion():   # 🔴 ONLY CHANGE ADDED
            QMessageBox.warning(self.parent, "Biometric", "Liveness check failed.")
            return False

        img = self._capture_image()
        if img is None:
            return False

        emb = self._get_embedding(img)
        if emb is None:
            return False

        emb_bytes = emb.astype(np.float32).tobytes()
        encoded = base64.b64encode(emb_bytes).decode()

        self.db.save_config("face_embedding", encoded)

        QMessageBox.information(self.parent, "Biometric", "Face registered successfully.")
        return True

    # ------------------------------------------------------
    # Authenticate face + liveness check
    # ------------------------------------------------------
    def authenticate(self):
        stored = self.db.get_config("face_embedding")

        if stored is None:
            QMessageBox.warning(self.parent, "Biometric", "No biometric registered.")
            return False

        # 🔴 LIVENESS CHECK BEFORE MATCHING
        QMessageBox.information(self.parent, "Liveness", "Please move your head or blink.")
        if not self._check_liveness_motion():   # ONLY CHANGE ADDED
            QMessageBox.warning(self.parent, "Biometric", "Liveness check failed.")
            return False

        stored_emb = np.frombuffer(base64.b64decode(stored), dtype=np.float32)

        img = self._capture_image()
        if img is None:
            return False

        current_emb = self._get_embedding(img)
        if current_emb is None:
            return False

        distance = np.linalg.norm(stored_emb - current_emb)

        if distance < 1.0:
            QMessageBox.information(self.parent, "Biometric", "Face match successful!")
            return True

        QMessageBox.warning(self.parent, "Biometric", "Face does not match.")
        return False
