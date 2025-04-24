import os
from datetime import datetime
from pprint import pprint
from typing import List, Optional
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType

from api.utils.loggers import create_logger
from api.utils.settings import settings
from decouple import config


logger = create_logger(__name__, log_file='logs/email.log')

async def send_email(
    recipients: List[str], 
    template_name: str, 
    subject: str, 
    attachments: Optional[List[str]]=None,
    template_data: Optional[dict] = {},
    apply_default_template_data: bool = True
):
    # from premailer import transform

    logger.info('Preparing to send email')
    
    # logger.info(f"MAIL_USERNAME: {config('MAIL_USERNAME')}")
    # logger.info(f"MAIL_PASSWORD: {config('MAIL_PASSWORD')}")
    # logger.info(f"MAIL_FROM: {config('MAIL_FROM')}")
    # logger.info(f"MAIL_PORT: {config('MAIL_PORT')} (type: {type(config('MAIL_PORT'))})")
    # logger.info(f"MAIL_SERVER: {config('MAIL_SERVER')}")
    # logger.info(f"MAIL_FROM_NAME: {config('MAIL_FROM_NAME')}")
    # logger.info(f"TEMPLATE_FOLDER: {config('TEMPLATE_FOLDER')}")
    
    try:
        conf = ConnectionConfig(
            MAIL_USERNAME=config('MAIL_USERNAME'),
            MAIL_PASSWORD=config('MAIL_PASSWORD'),
            MAIL_FROM=config('MAIL_FROM'),
            MAIL_PORT=int(config('MAIL_PORT')),
            MAIL_SERVER=config('MAIL_SERVER'),
            USE_CREDENTIALS=True,
            VALIDATE_CERTS=True,
            MAIL_STARTTLS=False,
            MAIL_SSL_TLS=True,
            MAIL_FROM_NAME=config('MAIL_FROM_NAME'),
            TEMPLATE_FOLDER=os.path.join("templates/email")
        )
        logger.info('Config set up')
        
        template_context = {
            'year': datetime.now().year,
            # 'app_url': config('APP_URL'),
            # 'app_name': config('APP_NAME'),
            # 'company_name': 'Wren HQ',
            # 'terms_url': config('TERMS_URL'),
            # 'privacy_policy_url': config('PRIVACY_POLICY_URL'),
            # 'support_email': 'mail@gmail.com',
            # 'help_center_url': '#',
            **template_data
        } if apply_default_template_data else template_data
        
        logger.info('Template context built')
        # logger.info(template_context)
        pprint(template_context)
        
        if attachments:
            message = MessageSchema(
                subject=subject,
                recipients=recipients,
                template_body=template_context,
                subtype=MessageType.html,
                attachments=attachments,
            )
        else:
            message = MessageSchema(
                subject=subject,
                recipients=recipients,
                template_body=template_context,
                subtype=MessageType.html
            )
        
        logger.info('Message schema set up')
        
        fm = FastMail(conf)
        
        logger.info(f'Sending mail from template `{template_name}`')
        await fm.send_message(message, template_name)
        
        logger.info(f"Email sent to {','.join(recipients)}")

    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        raise