/*
 * Copyright © 2016 Cask Data, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

/****************************
 * Global helper functions  *
 ****************************/

/* Global helper functions */
Array.prototype.unique = function () {
  return this.reduce(function (accum, current) {
    if (accum.indexOf(current) < 0) {
      accum.push(current);
    }
    return accum;
  }, []);
};

//getting global csrftoken for later usage
//var csrftoken = Cookies.get('csrftoken');
var csrftoken = $.cookie('csrftoken');

/* Protecting CSRF token being sent to other domains */
function csrfSafeMethod(method) {
    // these HTTP methods do not require CSRF protection
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}

/* Global setup csrf tokening for AJAX request*/
$.ajaxSetup({
    beforeSend: function(xhr, settings) {
        if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
        }
    }
});

/* Pop up an error notification on top right corner with amaran.js */
function popErrorNotification(message) {
  $.amaran({
    'theme': 'colorful',
    'content': {
      bgcolor: '#f42601',
      color: '#fff',
      message: message
    },
    'position': 'top right',
    'inEffect': 'slideTop',
    'closeButton': true,
    'sticky': true,
  });
}

/* A template of the operation column in the ACL listing table*/
function getACLOperationTemplate(role, actions) {
  return '<td><a><i class="fa fa-pencil-square-o pointer" aria-hidden="true" ' +
    'onclick="editACL(\'' +  role + '\')"></i></a>' +
    '<a><i class="fa fa-trash pointer" aria-hidden="true" ' +
  'onclick="delACL(\'' + role + '\',\'' + actions + '\')" style="padding-left: 8px"></i></a></td>';
}

/* */
function getRoleACLTemplate(path, actions) {
  return '<td><a><i class="fa fa-trash pointer" aria-hidden="true" ' +
    'onclick="deletePrivilegeByRole(\'' + path + '\',\'' + actions + '\')" ' +
    'style="padding-left: 8px"></i></a> </td>';
}

/* Authentication to cdap cluster */
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
    //window.location.reload();
    popErrorNotification(data["responseText"]);
  });
}

/* Tab switching of role-management and ACL management */
$(".nav-role").on("click", function () {
  $(".role-management").show();
  $(".privilege-management").hide();
  $(".nav-privilege").removeClass('active');
  $(".nav-role").addClass('active');
  refreshRoleTable();
});

$(".nav-privilege").on("click", function () {
  $(".privilege-management").show();
  $(".role-management").hide();
  $(".nav-privilege").addClass('active');
  $(".nav-role").removeClass('active');
});


/*************************************
 * Related to privileges managements *
 *************************************/

/* Handlers of click on an entity in jstree */
function entityClicked(entity, data) {
  var parents = entity.parents;
  if (parents.length % 2 === 1) {
    return;
  }
  // Construct the path to entity   eg. if user click on puchaseStream under default namespace,
  //  the string will look like  "/Namespace/default/Stream/purchaseStream"
  var treeStructString = "/" + entity.text.trim();
  for (var i = 0; i < parents.length - 2; i++) {
    parentText = data.instance.get_node(parents[i]).text.trim();
    // Even layer are entity types: Namespaces, Streams etc.
    if (i % 2 == 0) {
      parentText = parentText[0].toLowerCase() + parentText.substring(1);
    }
    treeStructString = "/" + parentText + treeStructString;
  }
  // Set heading and breadcrumb with entity path
  $('.acl-heading').html(treeStructString.substring(1));
  $('#acl-heading-breadcrumb').empty();
  var dividerSpan = '<span class="divider">/</span>';
  var breadcrumbContent = '';
  // The first one is always "Namespace", just discard it
  var entities = treeStructString.split("/");
  for (var i = 1; i < entities.length - 1; i++) {
    breadcrumbContent += "<li><a>" + entities[i] + " " + dividerSpan + "</a></li>";
  }
  breadcrumbContent += '<li class="active">' + entities[entities.length - 1] + '</li>';
  $('#acl-heading-breadcrumb').append(breadcrumbContent);

  // Update description
  refreshDetail(treeStructString);
}

/* Refresh description and ACLs of an entity */
function refreshDetail(treeStructString) {
  // Fetch entity details and privileges from backend api
  $.get("/cdap/details" + treeStructString, function (data) {
    $("#description-table-body").empty();
    var properties = ["name", "version", "id", "type", "scope", "description"];
    var tableContent = "";
    properties.forEach(function (prop) {
      if (data[prop]) {
        tableContent += "<tr><td>" + prop + "</td><td>" + data[prop] + "</td></tr>";
      }
    });
    $("#description-table-body").append(tableContent);

    $("#acl-table-body").empty();
    tableContent = "";
    privileges = data["privileges"];
    for (var role in privileges) {
      var actions = privileges[role]["actions"].unique().join(",");
      tableContent += "<tr><td>" + role + "</td><td>" + actions + "</td>" +
        getACLOperationTemplate(role, actions) + "<td></td></tr>";
    }
    $("#acl-table-body").append(tableContent);
  }).fail(function (data) {
    popErrorNotification(data["responseText"]);
  });
  // Fetch all the roles from backend
  $.get("/cdap/list_roles_by_group/" + treeStructString, function (data) {
    $(".user-group").empty();
    for (var i = 0; i < data.length; i++) {
      var option = document.createElement("option");
      option.text = data[i]["name"];
      $(".user-group").append(option);
    }
  }).fail(function (data) {
    popErrorNotification(data["responseText"]);
  });
}

function newACL() {
  $("#new-acl-popup").modal();
  setPrivCheckbox();
}

function delACL(role, actions) {
  var path = $(".acl-heading").text();
  // get data from backend
  $("body").css("cursor", "progress");
  $.ajax({
    type: "POST",
    url: "/cdap/revoke",
    data: {"role": role, "actions": actions.split(","), "path": path},
  }).done(function (data) {
    refreshDetail("/" + path);
    if (data.length > 0) {
      popErrorNotification(("Can not revoke some privileges as they are defined on upper layer entites at: " + data));
    }
  }).fail(function (data) {
    popErrorNotification(data["responseText"]);
  }).always(function () {
    $("body").css("cursor", "default");
  });
}

function editACL(role) {
  $(".user-group").val(role);
  newACL();
}

function saveACL() {
  var allActions = ["READ", "WRITE", "EXECUTE", "ADMIN", "ALL"];
  var role = $(".user-group").find(":selected").text();
  var path = $(".acl-heading").text();
  var actions = [];
  var checked = $("#new-acl-popup input:checked");
  for (var i = 0; i < checked.length; i++) {
    checked[i].checked = false;
    actions.push(checked[i].value);
  }
  $("body").css("cursor", "progress");
  $.ajax({
    type: "POST",
    url: "/cdap/revoke",
    data: {"role": role, "actions": allActions, "path": path},
  }).done(function () {
    $.ajax({
      type: "POST",
      url: "/cdap/grant",
      data: {"role": role, "actions": actions, "path": path},
      success: function () {
        refreshDetail("/" + path);
        $("body").css("cursor", "default");
      },
    });
  }).fail(function (data) {
    popErrorNotification(data["responseText"]);
  }).always(function () {
    $("body").css("cursor", "default");
  });
}

function setPrivCheckbox() {
  var role = $(".user-group").find(":selected").text();
  var tr = $("td").filter(function () {
    return $(this).text() == role;
  }).closest("tr");
  if (tr.length > 0) {
    var actions = tr.children()[1].textContent.split(",");
  } else {
    var actions = [];
  }
  // Set checkbox
  var checkboxes = $("#new-acl-popup input:CHECKBOX");
  for (var i = 0; i < checkboxes.length; i++) {
    checkboxes[i].checked = false;
    if (actions.indexOf(checkboxes[i].value) != -1) {
      checkboxes[i].checked = true;
    }
  }
}

/* Role management */
function getGroupMultiSelector(role) {
  $.get("/cdap/list_all_groups", function (groups) {
    var select = '<select class="group-selector" data-placeholder="None..." style="width:350px;" multiple>';
    groups.forEach(function (group) {
      select += $('<option></option>').val(group).html(group);
    });
    select += "</select>";
  }).fail(function (data) {
    popErrorNotification(data["responseText"]);
  });
}


function refreshRoleTable() {
  $(".list-role-table").bootstrapTable('destroy');
  $.get("/cdap/list_roles_by_group", function (data) {
    var dataField = [];
    data.forEach(function (item) {
      dataField.push({
        state: false,
        role: item.name,
        group: item.groups.join(","),
      });
    });
    $(".list-role-table").bootstrapTable({
      columns: [{
        field: 'state',
        checkbox: true,
        align: 'center',
      }, {
        field: 'role',
        title: 'Name'
      }, {
        field: 'group',
        title: 'Group'
      }],
      data: dataField
    });
  }).fail(function (data) {
    popErrorNotification(data["responseText"]);
  });
}

function deleteRole() {
  var selections = $(".list-role-table").bootstrapTable('getAllSelections');
  selections.forEach(function (item) {
    $.get("/cdap/drop_role/" + item.role, function () {
      $(".list-role-table").bootstrapTable('remove', {field: "role", values: [item.role]})
    });
  }).fail(function (data) {
    popErrorNotification(data["responseText"]);
  });
}

function saveRole() {
  $.get("/cdap/create_role/" + $("#new-rolename").val(), function () {
    $(".list-role-table").bootstrapTable('destroy');
    refreshRoleTable();
  }).fail(function (data) {
    popErrorNotification(data["responseText"]);
  });
}

function updateRoleACL(role) {
  $(".selected-role").html(role);

  $("#role-acl-table-body").empty();
  $.get("/cdap/list_privileges_by_role/" + role, function (data) {
    data.forEach(function (privilege) {
      // The first three item will be instance/CDAP/namespace. Strip them.
      var path = privilege.authorizables.split("/").slice(3).join("/");
      $("#role-acl-table-body").append("<tr><td>" + path + "</td><td>"
        + privilege.actions + "</td>" + getRoleACLTemplate(path, privilege.actions) + "<td></td></tr>");

    });
  }).fail(function (data) {
    popErrorNotification(data["responseText"]);
  });
}

function deletePrivilegeByRole(path, action) {
  var role = $('.selected-role').text();
  $("body").css("cursor", "progress");
  $.ajax({
    type: "POST",
    url: "/cdap/revoke",
    data: {"role": role, "actions": action.split(","), "path": path},
  }).done(function (data) {
    //tr.remove();
    updateRoleACL(role);
  }).fail(function (data) {
    popErrorNotification(data["responseText"]);
  }).always(function(){
    $("body").css("cursor", "default");
  });
}


function editRole() {
  $(".group-selector").empty();
  $(".group-selector").trigger("chosen:updated");

  var selections = $(".list-role-table").bootstrapTable('getAllSelections');
  if (selections.length == 0)  return;

  var item = selections[0];
  var affGroups = item.group.split(",");
  $("#edit-role-modal-title").html(item.role);
  $.get("/cdap/list_all_groups", function (groups) {
    groups.forEach(function (group) {
      if (affGroups.indexOf(group) == -1) {
        var option = $('<option></option>').val(group).html(group);
      } else {
        var option = $('<option selected></option>').val(group).html(group);
      }
      $(".group-selector").append(option);
    });

    $('#edit-role-popup').on('shown.bs.modal', function () {
      $(".group-selector").trigger("chosen:updated");
      $(".group-selector").chosen();
    });
    $('#edit-role-popup').modal();
  }).fail(function (data) {
    popErrorNotification(data["responseText"]);
  });
}


function saveEditedRole() {
  role = $("#edit-role-modal-title").text();
  var options = $(".group-selector")[0].options;
  var selected = [];
  for (var i = 0; i < options.length; i++) {
    if (options[i].selected) {
      console.log(options[i].text);
      selected.push(options[i].text);
    }
  }
  $.ajax({
    type: "POST",
    url: "/cdap/alter_role_by_group",
    data: {"role": role, "groups": selected},
  }).done(function () {
      refreshRoleTable();
    }
  ).fail(function (data) {
    popErrorNotification(data["responseText"]);
  });
}
