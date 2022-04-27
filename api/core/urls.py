from rest_framework.routers import DefaultRouter

from .views import LoginUserViewSet, TaskViewSet

router = DefaultRouter()


router.register('auth', LoginUserViewSet, basename='login')
router.register('tasks', TaskViewSet)

urlpatterns = router.urls
