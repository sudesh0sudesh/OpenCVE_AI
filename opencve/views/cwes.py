from flask import render_template, request

# from opencve.controllers.cwes import get_cwes
from opencve.controllers.cwes import CweController
from opencve.controllers.main import main


@main.route("/cwe")
def cwes():
    objects, _, pagination = CweController.list(request.args)
    return render_template("cwes.html", cwes=objects, pagination=pagination)
