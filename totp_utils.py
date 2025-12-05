import pyotp
import qrcode
from PIL import Image

def generate_totp_secret() -> str:
    return pyotp.random_base32()

def get_totp_uri(secret: str, account_name: str, issuer: str) -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=account_name, issuer_name=issuer)

def generate_qr_code(uri: str) -> Image.Image:
    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white")

def verify_totp(secret: str, code: str) -> bool:
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(code)
    except Exception:
        return False
