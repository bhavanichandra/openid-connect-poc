from rest_framework.serializers import ModelSerializer

from .models import User, Task


class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = (
            'id', 'username', 'email', 'first_name', 'last_name', 'is_staff', 'is_superuser', 'is_active',
            'date_joined')


class TaskSerializer(ModelSerializer):
    class Meta:
        model = Task
        fields = "__all__"
