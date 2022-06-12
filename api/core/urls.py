from django.urls import path

from .views import LoginUserViewSet, TaskViewSet, SSOLoginViewSet, EmailViewSet

urlpatterns = [
    path('login/', LoginUserViewSet.as_view({"post": "login"})),
    path('register/', LoginUserViewSet.as_view({"post": "register"})),
    path('tasks/', TaskViewSet.as_view({"get": "list", "post": "create"})),
    # path('tasks/<int:pk>', LoginUserViewSet.as_view({"put": "update", "delete": "delete"})),
    # path('login/sso/', SSOLoginViewSet.as_view({"post": "generate_authorize_endpoint"})),
    path('send/', EmailViewSet.as_view({"post": "send_email"}))
]
