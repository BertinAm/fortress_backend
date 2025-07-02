from django.db import models

# Create your models here.
class LoginAttempt(models.Model): # create a model to track login attempts
    ip_address = models.GenericIPAddressField()  # store the IP address of the user
    username = models.CharField(max_length=255)  # store the username of the user
    was_successful = models.BooleanField(default=False)  # track if the login attempt was successful
    timestamp = models.DateTimeField(auto_now_add=True)   # store the timestamp of the login attempt

    class Meta:    # metadata for the model
        ordering = ['-timestamp']   # order by timestamp descending
        verbose_name = "Login Attempt"   # singular name for the model
        verbose_name_plural = "Login Attempts"    # plural name for the model

    def __str__(self):  # string representation of the model
        status = "Success" if self.was_successful else "Failed"   # determine the status of the login attempt
        return f"{self.timestamp} | {self.ip_address} | {self.username} | {status}"   # return a formatted string with the details of the login attempt