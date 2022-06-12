import hashlib
import os

from django.conf import settings
from django.contrib.auth.hashers import make_password, check_password
from django.template import loader
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet
import urllib.parse
import re
import base64
import jwt
from django.core.mail import EmailMultiAlternatives

from .models import User, Task
from .serializers import UserSerializer, TaskSerializer
from .utils import validate_token_and_get_user


class LoginUserViewSet(ViewSet):
    """
    Login User
    """
    permission_classes = [AllowAny]

    @action(methods=['post'], description="Login user", detail=False)
    def login(self, request):
        """
        Login User
        """
        email = request.data.get('email')
        password = request.data.get('password')
        if email is None or password is None:
            return Response({"success": False, "message": "Please provide both email and password", "data": None})
        try:
            user = User.objects.get(username=email)
            if not check_password(password, user.password):
                return Response({"success": False, "message": "Invalid username or password"}, status=401)
            try:
                token = Token.objects.get(user=user)
                token.delete()
            except Token.DoesNotExist:
                pass

            token = Token.objects.create(user=user)
            user_data = {
                "id": user.id,
                "name": user.get_full_name(),
                "username": user.username,
                "isSSOUser": user.is_sso,
                "SSOId": user.sso_id
            }
            return Response(
                {"success": True, "message": "User logged in", "data": {'token': token.key, "user": user_data}})
        except User.DoesNotExist:
            return Response({"success": False, "message": "User does not exist", "data": None})

    @action(methods=['post'], detail=False, description="Registers new user")
    def register(self, request):
        """
        Register New User
        """
        if not request.data:
            return Response(
                {"success": False, "message": "Please provide email, password and username, firstname and lastname",
                 "data": None})
        email = request.data.get('email')
        password = request.data.get('password')
        username = request.data.get('username')
        first_name = request.data.get('firstName')
        last_name = request.data.get('lastName')
        is_sso_user = request.data.get('sso') or False

        try:
            User.objects.get(username=email)
            return Response({"success": False, "message": "User already exists", "data": None})
        except User.DoesNotExist:
            user = User.objects.create(username=username, email=email, password=make_password(password),
                                       first_name=first_name,
                                       last_name=last_name,
                                       is_sso=is_sso_user)
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
            user_id = user_data.get('data').get('user_id')
            tasks = Task.objects.filter(user_id=user_id)
            task_serializer = TaskSerializer(tasks, many=True)
            return Response({"success": True, "message": "Tasks fetched!", "data": list(task_serializer.data)})
        else:
            return Response({**user_data, "message": "Invalid Token"})

    def delete(self, request, pk):
        try:
            token = request.auth.key
            user_data = validate_token_and_get_user(token)
            if not user_data.get('success'):
                return Response({"message": "Invalid Token", "success": False}, status=401)
            task = Task.objects.get(pk=pk)
            task.delete()
            return Response({"message": f"Successfully delete task {pk}", "success": True}, status=200)
        except Task.DoesNotExist:
            return Response({"message": f"Task with id: {pk} doesn't exists", "success": False}, status=404)
        except Exception as ex:
            return Response({"message": f"Unexpected error: {str(ex)}", "success": False}, status=500)

    def update(self, request, pk):
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

    def _generate_session(self, username):
        try:
            user = User.objects.get(username=username)
            if not user.is_sso:
                return "Not an SSO User", False
            try:
                token = Token.objects.get(user=user)
                token.delete()
            except Token.DoesNotExist:
                token = Token.objects.create(user_id=user.id)
            user_data = {
                "id": user.id,
                "name": user.get_full_name(),
                "username": user.username,
                "isSSOUser": user.is_sso,
                "SSOId": user.sso_id
            }
            return {"token": token, user: user_data}, True
        except User.DoesNotExist:
            return "User does not exist", False
        except Exception as ex:
            return f"Unexpected Error: {str(ex)}", False

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
            return Response({"success": True, "data": response_data, "message": "Authorize endpoint generated"},
                            status=200)
        except Exception as e:
            return Response({"success": False, "data": None, "message": f"Unexpected Error: {str(e)}"}, status=500)

    def generate_token(self, request):
        try:
            body = request.data
            id_token = body.get('idToken')
            decoded_id_token = jwt.decode(id_token)
            user_session, error = self._generate_session(username=decoded_id_token.get("data"))
            if error:
                return Response({"success": False, "data": None, "message": user_session}, status=500)
            return Response({"success": True, "data": user_session, "message": "User session generated"}, status=200)

        except Exception as ex:
            return Response({"success": False, "data": None, "message": f"Unexpected Error: {str(ex)}"}, status=500)


class EmailViewSet(ViewSet):
    permission_classes = [AllowAny]

    def send_email(self, request):
        to = "bhavanichandra9@gmail.com"
        subject = "Test Email"
        settings_dir = os.path.dirname(__file__)
        project_root = os.path.abspath(os.path.dirname(settings_dir))
        html_template = os.path.join(project_root, 'static/email_templates/credentials-share-email.html')
        html_message = loader.render_to_string(html_template, {
            "domain": "https://google.com/",
            "logo_url": "https://www.logolynx.com/images/logolynx/e3/e31181990fa18403f14bd4bce5fbdf8d.jpeg",
            "client_logo": None,
            "username": "testuser",
            "email": "test-user@test.com",
            "subject": subject,
            "is_sso": True,
            "password": None,
            "idp": "BuyerIDM"
        })

        # {
        #     "domain": "https://google.com/",
        #     "logo_url": "https://www.logolynx.com/images/logolynx/e3/e31181990fa18403f14bd4bce5fbdf8d.jpeg",
        #     "client_logo": "https://www.logolynx.com/images/logolynx/e3/e31181990fa18403f14bd4bce5fbdf8d.jpeg",
        #     "username": "testuser",
        #     "client": "Cisco",
        #     "email": "test-user@test.com",
        #     "subject": subject,
        #     "is_sso": False,
        #     "password": "H3ll0W0r1d",
        # }

        # Forgot Password Payload

        # html_message = loader.render_to_string(html_template, {
        #     "domain": "https://google.com/",
        #     "logo_url": "https://www.logolynx.com/images/logolynx/e3/e31181990fa18403f14bd4bce5fbdf8d.jpeg",
        #     "username": "testuser",
        #     "email": "test-user@test.com",
        #     "subject": subject,
        #     "password": "Somepassword"
        # })
        from_email = "test@gmail.com"
        text_content = 'Test email to check conditional template'

        msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
        msg.attach_alternative(html_message, "text/html")
        try:
            msg.send()
            return Response({"message": "Email Sent"}, status=200)
        except Exception as ex:
            return Response({"message": f"Error sending email: {str(ex)}"})
