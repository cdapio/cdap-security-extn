
<%!
def is_selected(section, matcher):
  if section == matcher:
    return "active"
  else:
    return ""
%>

<%def name="menubar(section='')">
  <div class="navbar navbar-inverse navbar-fixed-top nokids">
    <div class="navbar-inner">
      <div class="container-fluid">
        <div class="nav-collapse">
          <ul class="nav">
            <li class="currentApp">
              <a href="/cdap">
                <img src="${ static('cdap/art/icon_cdap_48.png') }" class="app-icon" />
                CDAP
              </a>
             </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</%def>
