# Adapted from Rohit's Project 2

from typing import Any, Dict


class HttpRequest:
	"""
	Represents a request in HTTP.
	Provides an API to compose a request and then build
	a final string that can be sent over the wire.
	"""
	HTTP_VERSION = 1.1

	HTTP_METHOD_GET = "GET"
	HTTP_METHOD_POST = "POST"

	def __init__(self, target: str, method: str = HTTP_METHOD_GET):
		assert method in (
			HttpRequest.HTTP_METHOD_GET, HttpRequest.HTTP_METHOD_POST
		)

		self.method = method
		self.target = target
		self.headers = {
			"connection": "keep-alive",  # to re-use the same TCP connection for subsequent requests
		}
		self.payload = ""

	def header(self, key: str, val: Any):
		# Add a header key-value pair.
		# headers are case-insensitive, lower-case makes it easy to process
		key = key.lower()

		# append the value if there's already one, else set a new one
		if key in self.headers.keys():
			self.headers[key] += "; " + val
		else:
			self.headers[key] = val

	def body(self, payload: str, content_type: str):
		# Set the body of the request and its corresponding content-type header
		# Also sets the content-length header
		if self.payload:  # for idempotency
			raise ValueError("Payload already set")

		self.header("content-type", content_type)
		self.header("content-length", len(payload))
		self.payload = payload

	def build(self) -> str:
		# Build a HTTP request string out of the given params.
		request = f"{self.method} {self.target} HTTP/{HttpRequest.HTTP_VERSION}\r\n"

		for key, val in self.headers.items():
			request += f"{key}: {val}\r\n"

		if self.payload:
			request += "\r\n" + self.payload

		return request + "\r\n"
