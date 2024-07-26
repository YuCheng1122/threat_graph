from elasticsearch import Elasticsearch, NotFoundError
from elasticsearch_dsl import Search
import logging

from ..config import ELASTICSEARCH_HOST, ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD

# Configure Elasticsearch with authentication
es = Elasticsearch(
    [ELASTICSEARCH_HOST],
    http_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD),
    headers={"Content-Type": "application/json"},
    http_compress=True,
    max_retries=3,
    retry_on_timeout=True,
    timeout=30,
    verify_certs=False  # Disable SSL certificate verification
)

class Node:
    index = "nodes"

    @staticmethod
    def save(node_data):
        """Save node data to Elasticsearch."""
        try:
            es.index(index=Node.index, id=node_data['id'], body=node_data)
        except Exception as e:
            logging.error(f"Error saving node: {e}", exc_info=True)
            raise

    @staticmethod
    def get(node_id):
        """Retrieve a node from Elasticsearch by ID."""
        try:
            return es.get(index=Node.index, id=node_id)['_source']
        except NotFoundError:
            return None
        except Exception as e:
            logging.error(f"Error getting node: {e}", exc_info=True)
            raise

    @staticmethod
    def get_nodes_by_time_range(start_time, end_time):
        """Retrieve nodes within a specified time range."""
        try:
            s = Search(using=es, index=Node.index).filter('range', timestamp={'gte': start_time, 'lte': end_time})
            return [hit.to_dict() for hit in s.scan()]
        except Exception as e:
            logging.error(f"Error getting nodes by time range: {e}", exc_info=True)
            raise

    @staticmethod
    def get_all_nodes():
        """Retrieve all nodes."""
        try:
            s = Search(using=es, index=Node.index).query("match_all")
            return [hit.to_dict() for hit in s.scan()]
        except Exception as e:
            logging.error(f"Error getting all nodes: {e}", exc_info=True)
            raise

class Edge:
    index = "edges"

    @staticmethod
    def save(edge_data):
        """Save edge data to Elasticsearch."""
        try:
            es.index(index=Edge.index, id=f"{edge_data['source']}-{edge_data['target']}", body=edge_data)
        except Exception as e:
            logging.error(f"Error saving edge: {e}", exc_info=True)
            raise

    @staticmethod
    def get(edge_id):
        """Retrieve an edge from Elasticsearch by ID."""
        try:
            return es.get(index=Edge.index, id=edge_id)['_source']
        except NotFoundError:
            return None
        except Exception as e:
            logging.error(f"Error getting edge: {e}", exc_info=True)
            raise

    @staticmethod
    def get_edges_by_time_range(start_time, end_time):
        """Retrieve edges within a specified time range."""
        try:
            s = Search(using=es, index=Edge.index).filter('range', timestamp={'gte': start_time, 'lte': end_time})
            return [hit.to_dict() for hit in s.scan()]
        except Exception as e:
            logging.error(f"Error getting edges by time range: {e}", exc_info=True)
            raise

    @staticmethod
    def get_all_edges():
        """Retrieve all edges."""
        try:
            s = Search(using=es, index=Edge.index).query("match_all")
            return [hit.to_dict() for hit in s.scan()]
        except Exception as e:
            logging.error(f"Error getting all edges: {e}", exc_info=True)
            raise
