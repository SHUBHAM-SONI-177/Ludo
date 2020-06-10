from django.db import models

class user(models.Model):
    name=models.CharField(max_length=50)
    email=models.EmailField()
    password=models.CharField(max_length=1000,default='None')
    profilePic=models.ImageField(null=True)
    isActive=models.BooleanField(null=True)
    def __str__(self):
        return self.email