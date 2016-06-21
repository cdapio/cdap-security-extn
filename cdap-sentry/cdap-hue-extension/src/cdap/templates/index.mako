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
<link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.10.1/bootstrap-table.min.css">
<link href="//netdna.bootstrapcdn.com/bootstrap/3.0.0/css/bootstrap-glyphicons.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/chosen/1.5.1/chosen.min.css">
<link rel="stylesheet" href="//cdn.jsdelivr.net/jquery.amaran/0.5.4/amaran.min.css">
<link rel="stylesheet" href="/static/cdap/css/cdap.css">

## Use double hashes for a mako template comment
## Main body

<div class="container-fluid">
  <div class="card">
    <div class="card-body">
      % if unauthenticated:
        <h1>You are not authorized!</h1>
        <p hidden class="is_authenticated">False<p>
      % else:
      <div class="row-fluid">
        <div class="span2">
          <div class="sidebar-nav">
            <ul class="nav nav-list">
              <li class="nav-header">Privileges</li>
              <li class="active nav-privilege"><a href="javascript:void(0)" data-toggleSection="edit"><i
                  class="fa fa-sitemap fa-rotate-270"></i> Browse</a></li>
              <li class="nav-role"><a href="javascript:void(0)" data-toggleSection="roles"><i class="fa fa-cubes"></i>
                Roles</a></li>
            </ul>
          </div>
        </div>

      <div class="privilege-management">
        <div class="span4">
          <div id="jstree">
            <ul>
              <li> Namespaces
                % for name, namespace in entities.iteritems():
                  <ul>
                    <li>${name}
                      <ul>
                        % for key, value in namespace.iteritems():
                          % if value:
                            <li> ${key[0].upper() + key[1:]}
                              <ul>
                                % for item in value:
                                  % if key != "application":
                                    <li class="card-info"> ${item} </li>
                                  % else:
                                    <li class="card-info"> ${item}
                                      <ul>
                                        % for application_type, apps in value[item].iteritems():
                                          <li> ${application_type[0].upper() + application_type[1:]}
                                            <ul>
                                              % for app in apps:
                                                <li>${app["name"]}</li>
                                              % endfor
                                            </ul>
                                          </li>
                                        % endfor
                                      </ul>
                                    </li>
                                  % endif
                                % endfor
                              </ul>
                            </li>
                          % endif
                        % endfor
                      </ul>
                    </li>
                  </ul>
                %endfor
              </li>
            </ul>
          </div>
        </div>
      <div class="span4">
      <div class="acl-panel">
        <h4 class="acl-heading" id="selected-entity-heading"></h4>

        <ul class="breadcrumb" id="acl-heading-breadcrumb"></ul>

        <div class="acl-description">
          <table class="table table-hover table-condensed" id="description-table">
            <thead>
            <tr>
              <th>Property</th>
              <th>Value</th>
            </tr>
            </thead>
            <tbody id="description-table-body">
            <tr>
              <td></td>
              <td></td>
            </tr>
            <tr>
              <td></td>
              <td></td>
            </tr>
            <tr>
              <td></td>
              <td></td>
            </tr>
            </tbody>
          </table>
        </div>

        <div class="acl-management">
        </div>
      % endif
    </div>
    </div>
      <div class="role-management">
        <div class="span4"><h3>Roles</h3>
        </div>
        <div class="span4">
          <h3 class="selected-role">ACLs</h3>
        </div>
      </div>
    </div>

    </div>
    </div>
  </div>
</div>

<div class="modal fade myModal" id="popup" role="dialog">
  <div class="modal-header">
    <button type="button" class="close" data-dismiss="modal">&times;</button>
    <h4 class="modal-title">Login to secure CDAP cluster</h4>
  </div>
  <div class="modal-body">
    <label for="cdap_username">Name:</label>
    <input id="cdap_username" type="text"/>
    <label for="cdap_password">Password:</label>
    <input id="cdap_password" type="password"/>
  </div>
  <div class="modal-footer">
    <button onclick="cdap_submit()" type="button" class="btn btn-default" data-dismiss="modal">Login</button>
  </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jstree/3.2.1/jstree.min.js"></script>
<script type="text/javascript"
        src="https://cdnjs.cloudflare.com/ajax/libs/jquery-jsonview/1.2.3/jquery.jsonview.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.10.1/bootstrap-table.min.js"></script>
<script type="text/javascript"
        src="https://cdnjs.cloudflare.com/ajax/libs/chosen/1.5.1/chosen.jquery.min.js"></script>
<script src="//cdn.jsdelivr.net/jquery.amaran/0.5.4/jquery.amaran.min.js"></script>
<script type="text/javascript" src="/static/cdap/js/cdap.js"></script>

<script>
  $(document).ready(function () {
    $('.myModal').on('show.bs.modal', function (e) {
      $('.myModal').css("width", "700px");
      $('.myModal').css("z-index", "100000");
    });

    $('.myModal').on('hidden.bs.modal', function (e) {
      $('.myModal').css("width", "0px");
      $('.myModal').css("z-index", "-10");
    });

    if ($(".is_authenticated").text() == "False") {
      $("#popup").modal();
    }

    $('#jstree').on('changed.jstree', function (e, data) {
      var r = data.instance.get_node(data.selected[data.selected.length - 1])
      entityClicked(r, data);
    });

    $('#jstree').jstree(
        {
          "core": {
            "animation": 0,
            "check_callback": true,
            "themes": {
              "stripes": true, "theme": "default",
              "dots": true,
              "icons": true
            },
          },
          "types": {
            "#": {
              "max_children": 1,
              "max_depth": 4,
              "valid_children": ["root"]
            },
            "root": {
              "icon": "/static/3.3.1/assets/images/tree_icon.png",
              "valid_children": ["default"]
            },
            "default": {
              "valid_children": ["default"]
            },
            "file": {
              "icon": "glyphicon glyphicon-file",
              "valid_children": []
            }
          },
          "plugins": [
            "search", "types", "wholerow"
          ]
        });

    ## Open first level of jstree
    $('#jstree').jstree("open_node", $(".jstree-anchor"));
  });
</script>

${commonfooter(request, messages) | n,unicode}
