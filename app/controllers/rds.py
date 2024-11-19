from app.schemas.rds import RDSDetectionRequest, RDSDetectionResponse
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
