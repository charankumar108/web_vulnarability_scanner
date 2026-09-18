import sys
import os

# Add repository root to sys.path so app and its templates can be resolved
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.abspath(os.path.join(current_dir, "..", ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from serverless_wsgi import handle_request
from app import app

def handler(event, context):
    return handle_request(app, event, context)
