"""
CI/CD Test Route
GET /auth/test/cicd - Returns deployment info
"""

from datetime import datetime
from flask import jsonify

def register_test_routes(app):
    """Register CI/CD test routes"""

    @app.route('/auth/test/cicd', methods=['GET'])
    def test_cicd():
        """Test endpoint to verify CI/CD deployment"""
        return jsonify({
            "status": "success",
            "service": "Goalixa Auth",
            "message": "CI/CD pipeline is working! 🚀",
            "deployed_at": datetime.utcnow().isoformat(),
            "version": "test-cicd"
        })
