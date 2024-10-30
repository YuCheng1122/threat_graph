from sqlalchemy.orm import Session
from app.models.user_db import GroupSignup, UserSignup, SessionLocal
from app.models.user_db import UserModel
from app.models.wazuh_db import AgentModel
from app.models.manage_db import ManageModel
from typing import Dict
from logging import getLogger
from datetime import datetime, timedelta
from typing import Optional, List
logger = getLogger('app_logger')

class ManageController:

    @staticmethod
    def get_group_email_map(current_user: UserModel) -> Dict[str, str]:
        db: Session = SessionLocal()
        try:
            # Query to get group names and associated emails
            groups_with_emails = db.query(GroupSignup.group_name, UserSignup.email)\
                .join(UserSignup, GroupSignup.user_signup_id == UserSignup.id)\
                .all()
            
            # Returning a dictionary mapping group names to emails
            return {group_name: email for group_name, email in groups_with_emails}
        finally:
            db.close()

    @staticmethod
    def get_current_user():
        pass
    
    @staticmethod
    def toggle_user_status(user_id: int) -> bool:
        return ManageModel.toggle_disabled_status(user_id)

    @staticmethod
    def update_user_license(user_id: int, license_amount: int) -> bool:
        return ManageModel.update_license_amount(user_id, license_amount)

    @staticmethod
    async def get_total_agents(group_names: Optional[List[str]] = None):
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=30)  # Assuming we want to count agents active in the last 30 days
            agents = await AgentModel.load_agents(start_time, end_time, group_names)
            return len(agents)
        except Exception as e:
            logger.error(f"Error getting total agents: {str(e)}")
            raise

    @staticmethod
    def get_total_license(user_id: Optional[int] = None):
        try:
            if user_id:
                return ManageModel.get_user_license(user_id)
            else:
                return ManageModel.get_total_license()
        except Exception as e:
            logger.error(f"Error getting total license: {str(e)}")
            raise

    @staticmethod
    def get_users(db: Session):
        return ManageModel.get_all_users(db)

    @staticmethod
    def get_next_agent_name(current_user: UserModel) -> str:
        """Get next available agent name for the user"""
        user_groups = ManageModel.get_user_groups(current_user.id)
        return ManageModel.get_next_agent_name(current_user.username, user_groups)
