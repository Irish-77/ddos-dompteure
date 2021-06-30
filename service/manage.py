from app import create_app
from app.model import *


app = create_app()


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0')