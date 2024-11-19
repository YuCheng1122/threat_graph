from datetime import datetime
from app.schemas.rds import RDSDetectionRequest, RDSDetectionResponse, RDSGetResponse, RDSDetectionRecord
from app.models.rds_db import RDSModel
from app.ext.error import ElasticsearchError
from logging import getLogger

# Get the centralized logger
logger = getLogger('app_logger')

class RDSController:
    """Controller for handling RDS detection operations."""

    @staticmethod
    async def save_detection(detection: RDSDetectionRequest) -> RDSDetectionResponse:
        """
        Save RDS detection events to the database.
        
        Args:
            detection (RDSDetectionRequest): The detection request containing events to save
            
        Returns:
            RDSDetectionResponse: Response indicating success/failure and number of events saved
            
        Raises:
            ElasticsearchError: If there's an error saving to the database
        """
        try:
            # Validate method
            if detection.method != "rds_detection":
                raise ValueError("Invalid method type. Must be 'rds_detection'")

            # Save events to database
            events_saved = await RDSModel.save_detection(detection)
            
            return RDSDetectionResponse(
                success=True,
                message="RDS detection events saved successfully",
                events_saved=events_saved
            )

        except ValueError as e:
            logger.error(f"Validation error in save_detection: {str(e)}")
            raise
        except ElasticsearchError as e:
            logger.error(f"Database error in save_detection: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in save_detection: {str(e)}")
            raise ElasticsearchError(f"Error saving detection: {str(e)}")

    @staticmethod
    async def get_detections(start_time: datetime, end_time: datetime, account: str = None) -> RDSGetResponse:
        """
        Retrieve RDS detection events from the database.
        
        Args:
            start_time (datetime): Start time for filtering records
            end_time (datetime): End time for filtering records
            account (str, optional): Account identifier to filter records
            
        Returns:
            RDSGetResponse: Response containing the list of detection records
            
        Raises:
            ElasticsearchError: If there's an error retrieving from the database
        """
        try:
            # Get detections from database
            detections = await RDSModel.get_detections(start_time, end_time, account)
            
            # Convert to RDSDetectionRecord objects
            records = [
                RDSDetectionRecord(
                    timestamp=datetime.fromisoformat(det["timestamp"].replace("Z", "+00:00")),
                    account=det["account"],
                    edge_name=det["edge_name"],
                    edge_ip=det["edge_ip"],
                    edge_mac=det["edge_mac"],
                    edge_os=det["edge_os"],
                    tag_id=det["tag_id"],
                    tag=det["tag"],
                    name=det["name"],
                    score=det["score"],
                    data_type=det["data_type"]
                )
                for det in detections
            ]
            
            return RDSGetResponse(
                success=True,
                total=len(records),
                records=records
            )

        except ElasticsearchError as e:
            logger.error(f"Database error in get_detections: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in get_detections: {str(e)}")
            raise ElasticsearchError(f"Error retrieving detections: {str(e)}")
