from flask import Flask, request, render_template_string

app = Flask(__name__)

# Basic HTML page that reflects input and simulates a fragile database backend
HTML_PAGE = """
<!DOCTYPE html>
<html>
<head><title>Vulnerable Test Lab</title></head>
<body style="background-color: #1a1a1a; color: white; font-family: sans-serif; padding: 40px;">
    <h2>Educational Test Target Application</h2>
    
    <div style="border: 1px solid #444; padding: 20px; margin-bottom: 20px;">
        <h3>Search Products (XSS Test)</h3>
        <form method="GET">
            <input type="text" name="q" placeholder="Search...">
            <button type="submit">Search</button>
        </form>
        {% if query %}
            <p>Search results for: {{ query | safe }}</p>
        {% endif %}
    </div>

    <div style="border: 1px solid #444; padding: 20px;">
        <h3>User Profile Lookup (SQLi Test)</h3>
        <form method="GET">
            <input type="text" name="id" placeholder="User ID...">
            <button type="submit">Lookup</button>
        </form>
        {% if user_id %}
            <p>Query Sent: <code>SELECT * FROM users WHERE id = '{{ user_id }}';</code></p>
            {% if " '" in user_id or "'" in user_id %}
                <div style="color: #ff6b6b; font-family: monospace; background: #000; padding: 10px;">
                    ERROR: Execution failed. You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''' at line 1.
                </div>
            {% else %}
                <p>Result: User Profile Found.</p>
            {% endif %}
        {% endif %}
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    query = request.args.get("q", "")
    user_id = request.args.get("id", "")
    return render_template_string(HTML_PAGE, query=query, user_id=user_id)

if __name__ == "__main__":
    # Runs the vulnerable application on port 8080
    app.run(debug=True, port=8080)