import hashlib

def sha256(content: str):
	return hashlib.sha256(content.encode("utf8")).hexdigest()
