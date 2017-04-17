//package co.cask.cdap.security.authorization.ranger.lookup.client;
//
//import org.apache.log4j.Logger;
//import org.apache.ranger.plugin.client.HadoopException;
//import org.apache.ranger.plugin.service.ResourceLookupContext;
//import org.apache.ranger.plugin.util.TimedEventUtil;
//
//import java.util.HashMap;
//import java.util.List;
//import java.util.Map;
//import java.util.concurrent.Callable;
//import java.util.concurrent.TimeUnit;
//
///**
// * CDAP Resource Manager
// */
//public class CDAPResourceMgr {
//  private static final String INSTANCE = "instance";
//  private static final String NAMESPACE = "namespace";
//
//  public static final Logger LOG = Logger.getLogger(CDAPResourceMgr.class);
//
//  public static HashMap<String, Object> connectionTest(String serviceName, Map<String, String> configs) throws
//    Exception {
//    HashMap<String, Object> ret;
//
//    LOG.debug("==> CDAPResourceMgr.connectionTest ServiceName: " + serviceName + "Configs" + configs);
//
//    try {
//      ret = CDAPClient.connectionTest(serviceName, configs);
//    } catch (HadoopException e) {
//      LOG.error("<== CDAPResourceMgr.connectionTest Error: " + e);
//      throw e;
//    }
//
//    LOG.debug("<== CDAPResourceMgr.connectionTest Result : " + ret);
//
//    return ret;
//  }
//
//  public static List<String> getResources(String serviceName, String serviceType, Map<String, String> configs,
//                                          ResourceLookupContext context) throws Exception {
//
//    String userInput = context.getUserInput();
//    String resource = context.getResourceName();
//    Map<String, List<String>> resourceMap = context.getResources();
//    List<String> resultList = null;
//    List<String> instanceList = null;
//    List<String> namespaceList = null;
//    String instanceName = null;
//    String namespaceName = null;
//
//
//    if (LOG.isDebugEnabled()) {
//      LOG.debug("<== CDAPResourceMgr.getResources()  UserInput: \"" + userInput + "\" resource : " + resource +
//                  " resourceMap: " + resourceMap);
//    }
//
//    if (userInput != null && resource != null) {
//      if (resourceMap != null && !resourceMap.isEmpty()) {
//        instanceList = resourceMap.get(INSTANCE);
//        namespaceList = resourceMap.get(NAMESPACE);
//      }
//      switch (resource.trim().toLowerCase()) {
//        case INSTANCE:
//          instanceName = userInput;
//          break;
//        case NAMESPACE:
//          namespaceName = userInput;
//          LOG.info("#### set the namespace name to : " + userInput);
//          break;
//        default:
//          break;
//      }
//    }
//
//    if (serviceName != null && userInput != null) {
//      try {
//
//
//          LOG.info("==> CDAPResourceMgr.getResources() UserInput: " + userInput + " configs: " + configs + " " +
//                      "instanceList: " + instanceList + " namespaceList: " + namespaceList);
//
//
//        final CDAPClient hiveClient = new CDAPConnectionMgr().getCDAPConnection(serviceName, serviceType, configs);
//
//        Callable<List<String>> callableObj = null;
//        final String finalinstanceName;
//        final String finalNamespaceName;
//
//        final List<String> finalinstanceList = instanceList;
//        final List<String> finalnamespaceList = namespaceList;
//
//
//        if (hiveClient != null) {
//          if (namespaceName != null
//            && !namespaceName.isEmpty()) {
//            // get the DBList for given Input
//            finalNamespaceName = namespaceName;
//            callableObj = new Callable<List<String>>() {
//              @Override
//              public List<String> call() {
//                LOG.info("#### calling list namespace with : " + finalNamespaceName);
//                return hiveClient.getNamespaces(finalNamespaceName,
//                                                finalnamespaceList);
//              }
//            };
//          }
//          if (callableObj != null) {
//            synchronized (hiveClient) {
//              resultList = TimedEventUtil.timedTask(callableObj, 5,
//                                                    TimeUnit.SECONDS);
//            }
//          } else {
//            LOG.error("Could not initiate at timedTask");
//          }
//        }
//      } catch (Exception e) {
//        LOG.error("Unable to get hive resources.", e);
//        throw e;
//      }
//    }
//
//    if (LOG.isDebugEnabled()) {
//      LOG.debug("<== CDAPResourceMgr.getCDAPResources() UserInput: " + userInput + " configs: " + configs + " " +
//                  "instanceList: " + instanceList + " namespaceList: "
//                  + namespaceList + "Result :" + resultList);
//
//    }
//    return resultList;
//
//  }
//}
