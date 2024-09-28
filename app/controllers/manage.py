from sqlalchemy.orm import Session
from app.models.manage_db import Group, UserSignup, SessionLocal
from app.models.user_db import UserModel
from typing import Dict
from logging import getLogger

logger = getLogger('app_logger')

class ManageController:
    @staticmethod
    def get_group_email_map(current_user: UserModel) -> Dict[str, str]:
        db: Session = SessionLocal()
        try:
            # Query to get group names and associated emails
            groups_with_emails = db.query(Group.group_name, UserSignup.email)\
                .join(UserSignup, Group.user_signup_id == UserSignup.id)\
                .all()
            
            # Returning a dictionary mapping group names to emails
            return {group_name: email for group_name, email in groups_with_emails}
        finally:
            db.close()

    @staticmethod
    def get_current_user():
        pass
    
    @staticmethod
    def approve_user(user_id: int) -> bool:
        return UserSignup.update_disabled_status(user_id, False)

    @staticmethod
    def update_user_license(user_id: int, license_amount: int) -> bool:
        return UserSignup.update_license_amount(user_id, license_amount)