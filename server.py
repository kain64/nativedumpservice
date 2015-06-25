from flask import Flask, Response, stream_with_context, send_file

from dumputils import DumpUtils

app = Flask(__name__)


@app.route("/createminidump/<pid>")
def create_mini_dump(pid):
    try:
        utils = DumpUtils(int(pid))
        file = utils.create_mini_dump()
        return send_file(file)
    except Exception as ex:
        print(ex)




if __name__ == "__main__":
    app.run(port=500)
