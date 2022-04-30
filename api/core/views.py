import hashlib
import os

from django.conf import settings
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet
import urllib.parse
import re
import base64

from .models import User, Task
from .serializers import UserSerializer, TaskSerializer
from .utils import validate_token_and_get_user


class LoginUserViewSet(ViewSet):
    """
    Login User
    """
    permission_classes = [AllowAny]

    def get_query_set(self):
        return User.objects.all()

    @action(methods=['post'], description="Login user", detail=False, url_path="login", url_name="login")
    def login(self, request):
        """
        Login User
        """
        email = request.data.get('email')
        password = request.data.get('password')
        if email is None or password is None:
            return Response({"success": False, "message": "Please provide both email and password", "data": None})
        try:
            user = User.objects.get(username=email, password=password)
            try:
                token = Token.objects.get(user=user)
                token.delete()
            except Token.DoesNotExist:
                pass

            token = Token.objects.create(user=user)
            return Response({"success": True, "message": "User logged in", "data": {'token': token.key}})
        except User.DoesNotExist:
            return Response({"success": False, "message": "User does not exist", "data": None})

    @action(methods=['post'], detail=False, description="Registers new user", url_path="register", url_name="register")
    def register(self, request):
        """
        Register New User
        """
        email = request.data.get('email')
        password = request.data.get('password')
        username = request.data.get('username')
        if email is None or password is None or username is None:
            return Response({"success": False, "message": "Please provide  email, password and username", "data": None})
        try:
            User.objects.get(username=email)
            return Response({"success": False, "message": "User already exists", "data": None})
        except User.DoesNotExist:
            user = User.objects.create(username=username, email=email, password=password)
            user.save()
            return Response({"success": True, "message": "User registered", "data": UserSerializer(user).data})


class TaskViewSet(ViewSet):
    """
    Task ViewSet
    """
    queryset = Task.objects.all()
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        try:
            token = request.auth.key
            user_data = validate_token_and_get_user(token)
            if user_data.get('success'):
                body = request.data
                body["user"] = user_data.get('data').get('user_id')
                task_serializer = TaskSerializer(data=body)
                task_serializer.is_valid(raise_exception=True)
                task_serializer.save()
                return Response(
                    {"success": True, "message": "Task Created Successfully", "data": body})
            else:
                return Response({**user_data, "message": "Invalid Token"})
        except Exception as e:
            return Response({"success": False, "message": e.__str__(), "data": None})

    def list(self, request):
        token = request.auth.key
        user_data = validate_token_and_get_user(token)
        if user_data.get("success"):
            tasks = Task.objects.all()
            task_serializer = TaskSerializer(tasks, many=True)
            return Response({"success": True, "message": "Tasks fetched!", "data": list(task_serializer.data)})
        else:
            return Response({**user_data, "message": "Invalid Token"})

    def update(self, request, pk=None):
        try:
            token = request.auth.key
            user_data = validate_token_and_get_user(token)
            if user_data.get('success'):
                try:
                    instance = Task.objects.get(id=pk)
                    body = request.data
                    body["user"] = user_data.get('data').get('user_id')
                    task_serializer = TaskSerializer(data=body, instance=instance)
                    task_serializer.is_valid(raise_exception=True)
                    task_serializer.save()
                    return Response(
                        {"success": True, "message": "Task Created Successfully", "data": body})
                except Task.DoesNotExist:
                    return Response(
                        {"success": False, "message": "Task Doesn't Exists", "data": None})
            else:
                return Response({**user_data, "message": "Invalid Token"})
        except Exception as e:
            return Response({"success": False, "message": e.__str__(), "data": None})


class SSOLoginViewSet(ViewSet):
    permission_classes = [AllowAny]

    def _generate_code_challenge(self, method):
        os_generated_rand_str = os.urandom(40)
        code_verifier = base64.urlsafe_b64encode(os_generated_rand_str).decode('utf8')
        sanitized_code_verifier = re.sub('[^a-zA-Z0-9]+', '', code_verifier)
        if method == 'plain':
            return sanitized_code_verifier, sanitized_code_verifier
        # Base64 encoded string of sha256 string of code_verifier
        pkce_challenge_code = hashlib.sha256(sanitized_code_verifier.encode('utf8')).digest()
        challenge_code = base64.urlsafe_b64encode(pkce_challenge_code).decode('utf8')
        challenge_code = challenge_code.replace("=", "")
        return challenge_code, sanitized_code_verifier

    def generate_authorize_endpoint(self, request):
        try:
            body = request.data
            tenant_id = body.get('tenant_id')
            client_id = settings.CLIENT_ID
            code_challenge_method = body.get('challenge_code_method')
            if not body:
                return Response({"message": "Please send request body", "success": False}, status=400)
            url = f"{settings.IDM_BASE_URI}authorize"
            code_challenge, code_verifier = self._generate_code_challenge(code_challenge_method)
            params = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": f"{settings.REDIRECT_URL}/?tenant_id={tenant_id}",
                "scope": "openid profile email",
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method
            }
            response_data = {
                "url": url + urllib.parse.urlencode(params),
                "code_verifier": code_verifier,
                "tenant_id": tenant_id
            }
            return Response({"success": True, "data": response_data}, status=200)
        except Exception as e:
            return Response({"success": False, "data": str(e)}, status=500)
