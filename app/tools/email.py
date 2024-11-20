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
        申請憑證數量：{license_amount} 組
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
                            <td style="padding: 8px 0;"><strong>申請憑證數量：</strong></td>
                            <td style="padding: 8px 0;">{license_amount} 組</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0;"><strong>申請時間：</strong></td>
                            <td style="padding: 8px 0;">{signup_time.strftime('%Y-%m-%d %H:%M:%S')}</td>
                        </tr>
                    </table>
                </div>
                
                <p>請儘速登入管理後台進行帳號審核作業。</p>
                <p><a href="https://dashboard.avocadoai.xyz/" style="color: #3498db;">點擊此處前往管理後台</a></p>
                
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
            # 過濾掉空的郵件地址
            admin_emails = [email.strip() for email in cls.ADMIN_EMAILS if email.strip()]
            if not admin_emails:
                logger.error("No valid admin email addresses configured")
                return

            msg, _ = cls.create_signup_email(username, company_name, email, 
                                        license_amount, signup_time)
            
            # 設置所有收件者
            msg['To'] = ', '.join(admin_emails)
            
            with smtplib.SMTP(cls.SMTP_SERVER, cls.SMTP_PORT) as server:
                server.starttls()
                server.login(cls.SENDER_EMAIL, cls.EMAIL_PASSWORD)
                
                try:
                    server.send_message(msg)
                    logger.info(f"Successfully sent notification to {len(admin_emails)} recipients")
                except Exception as e:
                    logger.error(f"Failed to send email: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Failed to send signup notification: {str(e)}")

    @classmethod
    def send_signup_received_notification(cls, username: str, company_name: str, to_email: str) -> None:
        """Send notification to user that their signup application is being processed"""
        if not cls.EMAIL_PASSWORD:
            logger.error("Email password not configured")
            return

        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = cls.SENDER_EMAIL
            msg['To'] = to_email
            msg['Subject'] = "帳號申請確認通知"

            # Plain text version
            text_content = f"""
            {company_name} 您好，
            
            感謝您申請使用我們的系統服務。我們已收到您的帳號申請，正在進行審核作業。
            
            申請資訊：
            ───────────────────
            公司名稱：{company_name}
            使用者帳號：{username}
            ───────────────────
            
            審核結果將會另行通知，請耐心等候。
            
            此為系統自動發送郵件，請勿直接回覆。
            """

            # HTML version
            html_content = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #2c3e50;">帳號申請確認通知</h2>
                    
                    <p>{company_name} 您好，</p>
                    
                    <p>感謝您申請使用我們的系統服務。我們已收到您的帳號申請，正在進行審核作業。</p>
                    
                    <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                        <h3 style="color: #2c3e50; margin-top: 0;">申請資訊</h3>
                        <table style="width: 100%; border-collapse: collapse;">
                            <tr>
                                <td style="padding: 8px 0;"><strong>公司名稱：</strong></td>
                                <td style="padding: 8px 0;">{company_name}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0;"><strong>使用者帳號：</strong></td>
                                <td style="padding: 8px 0;">{username}</td>
                            </tr>
                        </table>
                    </div>
                    
                    <p>審核結果將會另行通知，請耐心等候。</p>
                    
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
            
            with smtplib.SMTP(cls.SMTP_SERVER, cls.SMTP_PORT) as server:
                server.starttls()
                server.login(cls.SENDER_EMAIL, cls.EMAIL_PASSWORD)
                
                try:
                    server.send_message(msg)
                    logger.info(f"Successfully sent signup received notification to {to_email}")
                except Exception as e:
                    logger.error(f"Failed to send signup received email: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Failed to send signup received notification: {str(e)}")

    @classmethod
    def send_approval_notification(cls, username: str, company_name: str, to_email: str) -> None:
        """Send approval notification email to user"""
        if not cls.EMAIL_PASSWORD:
            logger.error("Email password not configured")
            return

        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = cls.SENDER_EMAIL
            msg['To'] = to_email
            msg['Subject'] = "帳號審核通過通知"

            # Plain text version
            text_content = f"""
            {company_name} 您好，
            
            您的帳號申請已通過審核，現在可以開始使用系統服務。
            
            帳號資訊：
            ───────────────────
            公司名稱：{company_name}
            使用者帳號：{username}
            ───────────────────
            
            請點擊以下連結登入系統：
            https://dashboard.avocadoai.xyz/
            
            此為系統自動發送郵件，請勿直接回覆。
            """

            # HTML version
            html_content = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #2c3e50;">帳號審核通過通知</h2>
                    
                    <p>{company_name} 您好，</p>
                    
                    <p>您的帳號申請已通過審核，現在可以開始使用系統服務。</p>
                    
                    <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                        <h3 style="color: #2c3e50; margin-top: 0;">帳號資訊</h3>
                        <table style="width: 100%; border-collapse: collapse;">
                            <tr>
                                <td style="padding: 8px 0;"><strong>公司名稱：</strong></td>
                                <td style="padding: 8px 0;">{company_name}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0;"><strong>使用者帳號：</strong></td>
                                <td style="padding: 8px 0;">{username}</td>
                            </tr>
                        </table>
                    </div>
                    
                    <p>請點擊以下連結登入系統：</p>
                    <p><a href="https://dashboard.avocadoai.xyz/" style="color: #3498db;">登入系統</a></p>
                    
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
            
            with smtplib.SMTP(cls.SMTP_SERVER, cls.SMTP_PORT) as server:
                server.starttls()
                server.login(cls.SENDER_EMAIL, cls.EMAIL_PASSWORD)
                
                try:
                    server.send_message(msg)
                    logger.info(f"Successfully sent approval notification to {to_email}")
                except Exception as e:
                    logger.error(f"Failed to send approval email: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Failed to send approval notification: {str(e)}")
