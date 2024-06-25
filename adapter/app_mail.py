from fastapi_mail import FastMail

from config import MailConfig


class AppMail:
    """
    AppMail is a class that provides a convenient interface for sending emails from the application.
    """

    def __init__(self):
        self.mail_conf = MailConfig.connection_config()

    async def send_mail(self, msg_schema, template_name):
        """
        send_mail is a function that sends an email using the provided JSON schema and email template.

        :param msg_schema: A JSON schema for the email to be sent, containing the subject, recipients, and body of the email.
        :param template_name:  Name of the email template to be used for formatting the email.
        :return: None
        """
        fm = FastMail(self.mail_conf)
        await fm.send_message(msg_schema, template_name=template_name)
