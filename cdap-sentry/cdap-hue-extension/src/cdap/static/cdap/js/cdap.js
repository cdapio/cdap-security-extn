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
  console.log(breadcrumbContent);
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
  }).fail(function (data) {
    popErrorNotification(data["responseText"]);
  });
}
