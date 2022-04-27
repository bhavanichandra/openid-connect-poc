from rest_framework.authtoken.models import Token
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

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
