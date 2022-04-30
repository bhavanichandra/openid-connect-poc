from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import LoginUserViewSet, TaskViewSet,SSOLoginViewSet

router = DefaultRouter()


router.register('auth', LoginUserViewSet, basename='login')
router.register('tasks', TaskViewSet)

urlpatterns = [
    path('login/sso/', SSOLoginViewSet.as_view({"post": "generate_authorize_endpoint"}))
]

urlpatterns += router.urls
