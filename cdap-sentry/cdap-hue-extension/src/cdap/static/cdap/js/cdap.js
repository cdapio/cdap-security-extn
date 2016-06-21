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

/* Remove duplicate item in an array */
Array.prototype.unique = function () {
  return this.reduce(function (accum, current) {
    if (accum.indexOf(current) < 0) {
      accum.push(current);
    }
    return accum;
  }, []);
};

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
  if (parents.length % 2 == 1) {
    return;
  }
  // Construct the path to entity
  var treeStructString = "/" + entity.text.trim();
  for (var i = 0; i < parents.length - 2; i++) {
    parentText = data.instance.get_node(parents[i]).text.trim();
    if (i % 2 == 0) {
      parentText = parentText[0].toLowerCase() + parentText.substring(1, parentText.length);
    }
    treeStructString = "/" + parentText + treeStructString;
  }
  // Set heading and breadcrumb with entity path
  $('.acl-heading').html(treeStructString.substring(1, treeStructString.length));
  $('#acl-heading-breadcrumb').empty();
  var dividerSpan = '<span class="divider">/</span>';
  var entities = treeStructString.split("/");
  for (var i = 1; i < entities.length - 1; i++) {
    $('#acl-heading-breadcrumb').append("<li><a>" + entities[i] + " " + dividerSpan + "</a></li>");
  }
  $('#acl-heading-breadcrumb').append('<li class="active">' + entities[entities.length - 1] + '</li>');
  // Update description
  refresfDetail(treeStructString);
}

/* Refresh description and ACLs of an entity */
function refresfDetail(treeStructString) {
  // Fetch entity details and privileges from backend api
  $.get("/cdap/details" + treeStructString, function (data) {
    $("#description-table-body").empty();
    var properties = ["name", "version", "id", "type", "scope", "description"];
    properties.forEach(function (prop) {
      if (data[prop]) {
        //description[prop] = data[prop];
        $("#description-table-body").append("<tr><td>" + prop + "</td><td>" + data[prop]) + "</td></tr>";
      }
    });
  }).fail(function (data) {
    popErrorNotification(data["responseText"]);
  });
}
