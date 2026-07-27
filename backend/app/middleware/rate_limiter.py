"""
Production Security & Rate Limiting Middleware.
Membatasi jumlah permintaan per IP (Rate Limiting) serta menginjeksikan header keamanan ketat (Security Headers).
"""

import time
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Dict, Tuple

class RateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int = 120, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # Storage: IP -> (request_count, window_start_time)
        self.clients: Dict[str, Tuple[int, float]] = {}

    async def dispatch(self, request: Request, call_next) -> Response:
        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()

        # Cleanup old entries & handle rate limiting
        if client_ip in self.clients:
            count, start_time = self.clients[client_ip]
            if now - start_time > self.window_seconds:
                self.clients[client_ip] = (1, now)
            else:
                if count >= self.max_requests:
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={
                            "detail": "[SiteCure Protection] Rate limit exceeded. Too many requests. Please try again later."
                        }
                    )
                self.clients[client_ip] = (count + 1, start_time)
        else:
            self.clients[client_ip] = (1, now)

        # Call next middleware / route
        response = await call_next(request)

        # Inject Strict Production Security Headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Server"] = "SiteCure-Protected-Server"

        return response
