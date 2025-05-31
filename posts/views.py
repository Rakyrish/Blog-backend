from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login, authenticate
from django.contrib.auth.models import User
from rest_framework import generics, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Post
from .serializers import PostSerializer
from google.oauth2 import id_token
from google.auth.transport import requests
import json
import re
import os
import logging

logger = logging.getLogger(__name__)

class CookieLoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            logger.error("Missing username or password in CookieLoginView")
            return Response({
                'message': 'Username and password are required',
                'data': {}
            }, status=400)

        user = authenticate(username=username, password=password)
        if user is None:
            logger.warning(f"Authentication failed for username={username}")
            return Response({
                'message': 'Invalid credentials',
                'data': {}
            }, status=401)

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        response = Response({
            'message': 'Login successful',
            'data': {'username': user.username, 'email': user.email}
        })
        response.set_cookie(
            key='access_token',
            value=access_token,
            httponly=True,
            samesite='Lax',
            secure=os.getenv('DJANGO_ENV', 'development') == 'production'
        )
        return response

@csrf_exempt
def register(request):
    if request.method == 'OPTIONS':
        return JsonResponse({"message": "OK"}, status=200)

    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            email = data.get('email')
            password1 = data.get('password1')
            password2 = data.get('password2')

            if not all([username, email, password1, password2]):
                logger.error("Missing required fields in /api/reg")
                return JsonResponse({
                    "message": "All fields are required",
                    "data": {}
                }, status=400)

            if password1 != password2:
                logger.error("Passwords do not match in /api/reg")
                return JsonResponse({
                    "message": "Passwords do not match",
                    "data": {}
                }, status=400)

            if not re.match(r'\S+@\S+\.\S+', email):
                logger.error("Invalid email format")
                return JsonResponse({
                    "message": "Invalid email format",
                    "data": {}
                }, status=400)

            if User.objects.filter(email=email).exists():
                logger.warning("Email already registered")
                return JsonResponse({
                    "message": "Email already registered",
                    "data": {}
                }, status=400)

            if User.objects.filter(username=username).exists():
                logger.warning("Username already taken")
                return JsonResponse({
                    "message": "Username already taken",
                    "data": {}
                }, status=400)

            user = User.objects.create_user(
                username=username,
                email=email,
                password=password1
            )
            user.save()

            logger.info(f"User {username} registered via /api/reg")
            return JsonResponse({
                "message": "User registered",
                "data": {"username": user.username, "email": user.email}
            }, status=201)

        except Exception as e:
            logger.error(f"Signup error in /api/reg: {str(e)}")
            return JsonResponse({
                "message": "Server error",
                "data": {}
            }, status=500)

    return JsonResponse({
        "message": "Method not allowed",
        "data": {}
    }, status=405)

@csrf_exempt
def login_user(request):
    if request.method == 'OPTIONS':
        return JsonResponse({"message": "OK"}, status=200)

    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            password = data.get('password')

            if not username or not password:
                logger.error("Missing username or password in /api/login")
                return JsonResponse({
                    "message": "Username and password are required",
                    "data": {}
                }, status=400)

            user = authenticate(request, username=username, password=password)
            if user is None:
                logger.warning(f"Authentication failed for username={username}")
                return JsonResponse({
                    "message": "Invalid credentials",
                    "data": {}
                }, status=400)

            login(request, user)
            logger.info(f"User {user.username} logged in via /api/login")
            return JsonResponse({
                "message": "Login successful",
                "data": {"username": user.username, "email": user.email}
            }, status=200)

        except Exception as e:
            logger.error(f"Login error in /api/login: {str(e)}")
            return JsonResponse({
                "message": "Server error",
                "data": {}
            }, status=500)

    return JsonResponse({
        "message": "Method not allowed",
        "data": {}
    }, status=405)

@csrf_exempt
def google_signup(request):
    if request.method == 'OPTIONS':
        return JsonResponse({"message": "OK"}, status=200)

    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            token = data.get('token')

            if not token:
                logger.error("No token provided in google_signup")
                return JsonResponse({
                    "message": "Token is required",
                    "data": {}
                }, status=400)

            client_id = os.getenv('GOOGLE_CLIENT_ID')
            if not client_id:
                logger.error("Google Client ID not set in environment variables")
                return JsonResponse({
                    "message": "Server configuration error",
                    "data": {}
                }, status=500)

            idinfo = id_token.verify_oauth2_token(
                token,
                requests.Request(),
                client_id
            )

            google_id = idinfo['sub']
            email = idinfo['email']
            name = idinfo.get('name', '')

            if User.objects.filter(email=email).exists():
                logger.warning("User with email already exists")
                return JsonResponse({
                    "message": "User already exists",
                    "data": {}
                }, status=400)

            user = User.objects.create(
                username=f"google_{google_id}",  # Unique username to avoid conflicts
                email=email,
                first_name=name
            )
            user.set_unusable_password()
            user.save()
            login(request, user)

            logger.info(f"User {email} signed up via Google")
            return JsonResponse({
                "message": "Google signup successful",
                "data": {"email": email, "name": name}
            }, status=201)

        except ValueError as e:
            logger.error(f"Invalid Google token in google_signup: {str(e)}")
            return JsonResponse({
                "message": "Invalid Google token",
                "data": {}
            }, status=400)
        except Exception as e:
            logger.error(f"Google signup error: {str(e)}")
            return JsonResponse({
                "message": "Server error",
                "data": {}
            }, status=500)

    return JsonResponse({
        "message": "Method not allowed",
        "data": {}
    }, status=405)

@csrf_exempt
def google_login(request):
    if request.method == 'OPTIONS':
        return JsonResponse({"message": "OK"}, status=200)

    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            token = data.get('token')

            if not token:
                logger.error("No token provided in google_login")
                return JsonResponse({
                    "message": "Token is required",
                    "data": {}
                }, status=400)

            client_id = os.getenv('GOOGLE_CLIENT_ID')
            if not client_id:
                logger.error("Google Client ID not set in environment variables")
                return JsonResponse({
                    "message": "Server configuration error",
                    "data": {}
                }, status=500)

            idinfo = id_token.verify_oauth2_token(
                token,
                requests.Request(),
                client_id
            )

            google_id = idinfo['sub']
            email = idinfo['email']
            name = idinfo.get('name', '')

            user, _ = User.objects.get_or_create(
                username=f"google_{google_id}",  # Unique username to avoid conflicts
                defaults={'email': email, 'first_name': name}
            )
            login(request, user)

            logger.info(f"User {email} logged in via Google")
            return JsonResponse({
                "message": "Google login successful",
                "data": {"email": email, "name": name}
            }, status=200)

        except ValueError as e:
            logger.error(f"Invalid Google token in google_login: {str(e)}")
            return JsonResponse({
                "message": "Invalid Google token",
                "data": {}
            }, status=400)
        except Exception as e:
            logger.error(f"Google login error: {str(e)}")
            return JsonResponse({
                "message": "Server error",
                "data": {}
            }, status=500)

    return JsonResponse({
        "message": "Method not allowed",
        "data": {}
    }, status=405)

class PostListCreateView(generics.ListCreateAPIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)


class PostDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    permission_classes = [permissions.IsAuthenticated]