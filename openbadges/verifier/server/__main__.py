from flask import Flask, redirect, render_template, request
import json
import six

from openbadges.verifier import verify, utils

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024  # 4mb file upload limit


def request_wants_json():
    best = request.accept_mimetypes.best_match(['application/json', 'text/html'])
    return best == 'application/json' and request.accept_mimetypes[best] > request.accept_mimetypes['text/html']


@app.route("/")
def home():
    provided_url = request.args.get('url', "")
    l = [key for key in request.args.keys() if key.startswith('identity__')]
    recipient_profile = {'type': l[0] if l else ''}
    recipient_profile['value'] = request.args.get(recipient_profile['type'], "")
    return render_template('index.html', url=provided_url, recipient_profile=recipient_profile)


@app.route("/results", methods=['GET'])
def result_get_redirect():
    return redirect('/')


@app.route("/results", methods=['POST'])
def results():
    data = request.get_json()
    profile = None
    eduid_given = False
    if not data and isinstance(request.form.get('data'), six.string_types) or request.files:
        user_input = request.form['data'] if 'data' in request.form else None
        if 'image' in request.files and len(request.files['image'].filename):
            user_input = request.files['image']
        edu_id = request.form.get('profile')
        if edu_id:
            profile = {'id': edu_id}
            eduid_given = True
        else:
            profile = None
    elif data:
        user_input = data.get('data')
        if type(user_input) == dict:  # for API calls
            user_input = json.dumps(user_input)
        try:
            profile = data['profile']
            if isinstance(profile, six.string_types):
                profile = json.loads(profile)
        except (TypeError, ValueError, KeyError):
            pass

    verification_results = verify(user_input, recipient_profile=profile)
    errors = utils.get_errors(verification_results)
    badgeclass_data = utils.get_badgeclass(verification_results)
    issuer_data = utils.get_issuer(verification_results)
    assertion_data = utils.get_assertion(verification_results)

    assertion_image_url = None
    if badgeclass_data:
        assertion_image_url = badgeclass_data.get('image')

    assertion_image = utils.get_assertion_image(verification_results, assertion_image_url)
    extensions = utils.get_extensions(verification_results)

    if request_wants_json():
        return json.dumps(verification_results, indent=4), 200, {'Content-Type': 'application/json'}
    return render_template(
        'results.html',
        is_valid=verification_results.get('report', {}).get('valid'),
        error_count=verification_results.get('report', {}).get('errorCount'),
        errors=errors,
        eduid_given=eduid_given,
        badgeclass_data=badgeclass_data,
        issuer_data=issuer_data,
        assertion_data=assertion_data,
        assertion_image=assertion_image,
        extensions=extensions)


if __name__ == "__main__":
    app.run(debug=True)
