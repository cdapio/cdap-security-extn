## Copyright 2016 Cask Data, Inc.
##
## Licensed under the Apache License, Version 2.0 (the "License"); you may not
## use this file except in compliance with the License. You may obtain a copy of
## the License at
##
## http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
## WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
## License for the specific language governing permissions and limitations under
## the License.

<%!from desktop.views import commonheader, commonfooter %>
<%namespace name="shared" file="shared_components.mako" />

${commonheader("cdap", "cdap", user) | n,unicode}
${shared.menubar(section='mytab')}

<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/jstree/3.2.1/themes/default/style.min.css"/>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/jquery-jsonview/1.2.3/jquery.jsonview.css">
<link rel="stylesheet" href="/static/cdap/css/cdap.css">

<style>

</style>

## Use double hashes for a mako template comment
## Main body

<div class="container-fluid">
  <div class="card">
    <h2 class="card-heading simple">Entities</h2>
    <div class="card-body">
      % if unauthenticated:
        <h1>You are not authorized!</h1>
        <p hidden class="is_authenticated">False<p>
      % else:

      <div class="row-fluid">
        <div class="span8"></div>
      <div class="span4">
      % endif
    </div>
    </div>
    </div>

    <div class="modal fade myModal" id="popup" role="dialog">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal">&times;</button>
        <h4 class="modal-title">Login to secure CDAP cluster</h4>
      </div>
      <div class="modal-body">
        <label for="cdap_username">Username:</label>
        <input id="cdap_username" type="text"/>
        <label for="cdap_password">Password:</label>
        <input id="cdap_password" type="password"/>
      </div>
      <div class="modal-footer">
        <button onclick="cdap_submit()" type="button" class="btn btn-default" data-dismiss="modal">Login</button>
      </div>
    </div>
  </div>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jstree/3.2.1/jstree.min.js"></script>
<script type="text/javascript"
        src="https://cdnjs.cloudflare.com/ajax/libs/jquery-jsonview/1.2.3/jquery.jsonview.min.js"></script>
<script>
  function cdap_submit() {
    var username = $("#cdap_username").val();
    var password = $("#cdap_password").val();
    $.ajax({
      type: "POST",
      url: "/cdap/authenticate",
      data: {"username": username, "password": password}
    }).done(function () {
          window.location.reload();
        }
    ).fail(function (data) {
      console.log(data);
      alert(data["responseText"]);
      window.location.reload();
    });
  }

  $(document).ready(function () {
    $('.myModal').on('show.bs.modal', function (e) {
      $('.myModal').css("width", "700px");
    })
    $('.myModal').on('hidden.bs.modal', function (e) {
      $('.myModal').css("width", "0px");
    })

    if ($(".is_authenticated").text() == "False") {
      $("#popup").modal();
    }
  });
</script>

${commonfooter(request, messages) | n,unicode}

