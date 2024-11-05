import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from datetime import datetime
from logging import getLogger
from dotenv import load_dotenv

# Get the centralized logger
logger = getLogger('app_logger')

# Load environment variables from .env file
load_dotenv()

class EmailNotification:
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    SENDER_EMAIL = os.getenv("SENDER_EMAIL")
    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
    ADMIN_EMAILS = os.getenv("ADMIN_EMAILS", "").split(",")

    @classmethod
    def create_signup_email(cls, username: str, company_name: str, email: str, 
                          license_amount: int, signup_time: datetime) -> tuple[MIMEMultipart, str]:
        """Create email content for signup notification"""
        msg = MIMEMultipart('alternative')
        msg['From'] = cls.SENDER_EMAIL
        msg['Subject'] = f"新用戶註冊審核通知 - {company_name}"

        # Plain text version
        text_content = f"""
        系統管理者您好，
        
        收到新用戶註冊申請，詳細資訊如下：
        
        申請資訊：
        ───────────────────
        公司名稱：{company_name}
        註冊帳號：{username}
        註冊信箱：{email}
        授權數量：{license_amount}
        申請時間：{signup_time.strftime('%Y-%m-%d %H:%M:%S')}
        ───────────────────
        
        請儘速登入管理後台進行帳號審核作業。
        管理後台網址：https://dashboard.avocadoai.xyz/
        
        此為系統自動發送郵件，請勿直接回覆。
        """

        # HTML version
        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #2c3e50;">新用戶註冊審核通知</h2>
                
                <p>系統管理者您好，</p>
                
                <p>收到新用戶註冊申請，詳細資訊如下：</p>
                
                <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <h3 style="color: #2c3e50; margin-top: 0;">申請資訊</h3>
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="padding: 8px 0;"><strong>公司名稱：</strong></td>
                            <td style="padding: 8px 0;">{company_name}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0;"><strong>註冊帳號：</strong></td>
                            <td style="padding: 8px 0;">{username}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0;"><strong>註冊信箱：</strong></td>
                            <td style="padding: 8px 0;">{email}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0;"><strong>授權數量：</strong></td>
                            <td style="padding: 8px 0;">{license_amount}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0;"><strong>申請時間：</strong></td>
                            <td style="padding: 8px 0;">{signup_time.strftime('%Y-%m-%d %H:%M:%S')}</td>
                        </tr>
                    </table>
                </div>
                
                <p>請儘速登入管理後台進行帳號審核作業。</p>
                <p><a href="https://admin.yourcompany.com" style="color: #3498db;">點擊此處前往管理後台</a></p>
                
                <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                
                <p style="color: #666; font-size: 12px;">
                    此為系統自動發送郵件，請勿直接回覆。<br>
                    如有任何問題，請聯繫系統管理團隊。
                </p>
            </div>
        </body>
        </html>
        """

        # Attach both versions
        msg.attach(MIMEText(text_content, 'plain'))
        msg.attach(MIMEText(html_content, 'html'))
        
        return msg, html_content

    @classmethod
    def send_signup_notification(cls, username: str, company_name: str, email: str, 
                               license_amount: int, signup_time: datetime) -> None:
        """Send signup notification email to administrators"""
        if not cls.EMAIL_PASSWORD:
            logger.error("Email password not configured")
            return

        try:
            msg, _ = cls.create_signup_email(username, company_name, email, 
                                           license_amount, signup_time)
            
            with smtplib.SMTP(cls.SMTP_SERVER, cls.SMTP_PORT) as server:
                server.starttls()
                server.login(cls.SENDER_EMAIL, cls.EMAIL_PASSWORD)
                
                successful_sends = 0
                for admin_email in cls.ADMIN_EMAILS:
                    admin_email = admin_email.strip()
                    if not admin_email:
                        continue
                        
                    try:
                        msg['To'] = admin_email
                        server.send_message(msg)
                        successful_sends += 1
                        logger.info(f"Successfully sent notification to {admin_email}")
                    except Exception as e:
                        logger.error(f"Failed to send to {admin_email}: {str(e)}")
                
                logger.info(f"Email notification completed. Sent to {successful_sends}/{len(cls.ADMIN_EMAILS)} recipients")
                
        except Exception as e:
            logger.error(f"Failed to send signup notification: {str(e)}")