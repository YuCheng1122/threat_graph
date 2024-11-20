from sqlalchemy import func, select
from sqlalchemy.orm import Session
from app.models.user_db import GroupSignup, UserSignup, SessionLocal
from app.models.wazuh_db import AgentModel
from app.schemas.manage import UserInfo
from app.tools.email import EmailNotification
from logging import getLogger
from typing import List

logger = getLogger('app_logger')

class ManageModel:

    @staticmethod
    def toggle_disabled_status(user_id: int) -> bool:
        """
        Toggle the disabled status of a user and update group_signup.
        Only create group_signup entry when enabling a user (disabled -> enabled).
        Returns the new disabled status.
        """
        with SessionLocal() as session:
            try:
                user = session.query(UserSignup).filter(UserSignup.id == user_id).first()
                if user:
                    was_disabled = bool(user.disabled)
                    user.disabled = not user.disabled
                    user.update_date = func.now()
                    
                    if was_disabled and not user.disabled:
                        # Create group signup when enabling user
                        group_signup = GroupSignup(
                            group_name=user.username,
                            user_signup_id=user.id
                        )
                        
                        existing_group = session.query(GroupSignup).filter(
                            GroupSignup.group_name == user.username,
                            GroupSignup.user_signup_id == user.id
                        ).first()
                        
                        if not existing_group:
                            session.add(group_signup)
                        
                        # Send approval notification email
                        EmailNotification.send_approval_notification(
                            username=user.username,
                            company_name=user.company_name,
                            to_email=user.email
                        )
                    
                    session.commit()
                    return user.disabled
                return None
                
            except Exception as e:
                logger.error(f"Error in toggle_disabled_status: {str(e)}")
                session.rollback()
                raise

    @staticmethod
    def update_license_amount(user_id: int, license_amount: int):
        with SessionLocal() as session:
            user = session.query(UserSignup).filter(UserSignup.id == user_id).first()
            if user:
                user.license_amount = license_amount
                user.update_date = func.now()
                session.commit()
                return True
            return False

    @staticmethod
    def get_user_groups(user_id: int) -> List[str]:
        with SessionLocal() as session:
            user = session.query(UserSignup).filter(UserSignup.id == user_id).first()
            if user:
                return [group.group_name for group in user.groups]
            return []

    @staticmethod
    def get_user_license(user_id: int) -> int:
        with SessionLocal() as session:
            user = session.query(UserSignup).filter(UserSignup.id == user_id).first()
            return user.license_amount if user else 0

    @staticmethod
    def get_total_license() -> int:
        with SessionLocal() as session:
            result = session.execute(
                select(func.sum(UserSignup.license_amount))
            ).scalar()
            return result or 0

    @staticmethod
    def get_all_users(db: Session):
        users = db.query(UserSignup).filter(UserSignup.user_role != 'admin').all()
        return [
            UserInfo(
                user_id=user.id,
                id=user.id,
                username=user.username,
                email=user.email,
                company_name=user.company_name,
                license_amount=user.license_amount,
                disabled=bool(user.disabled)
            )
            for user in users
        ]
    
    @staticmethod
    def get_next_agent_name(username: str, group_names: List[str]) -> str:
        """
        Get the next available agent name based on existing agents
        Returns format like '{username}_001', '{username}_002', etc.
        """
        try:
            # Get existing agent names from latest agent details
            agent_details = AgentModel.get_latest_agent_details(group_names)
            existing_names = [agent['agent_name'] for agent in agent_details]
            
            # Find the highest number for this username
            max_num = 0
            prefix = f"{username}_"
            for name in existing_names:
                if name.startswith(prefix):
                    try:
                        num = int(name.split('_')[1])
                        max_num = max(max_num, num)
                    except (IndexError, ValueError):
                        continue
            
            # Generate next name
            next_num = max_num + 1
            next_name = f"{prefix}{next_num:03d}"  # Format: username_001, username_002, etc.
            
            return next_name
            
        except Exception as e:
            logger.error(f"Error in get_next_agent_name: {str(e)}")
            raise
