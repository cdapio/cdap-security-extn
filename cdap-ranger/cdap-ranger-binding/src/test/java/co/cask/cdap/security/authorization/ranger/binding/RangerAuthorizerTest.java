package co.cask.cdap.security.authorization.ranger.binding;

import co.cask.cdap.proto.ProgramType;
import co.cask.cdap.proto.id.EntityId;
import co.cask.cdap.proto.id.NamespaceId;
import co.cask.cdap.proto.security.Action;
import co.cask.cdap.proto.security.Principal;
import co.cask.cdap.security.spi.authorization.UnauthorizedException;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Test {@link RangerAuthorizer} through a policies stored in a file under resources/cdap-policies.json
 */
public class RangerAuthorizerTest {

  private static RangerAuthorizer authorizer;

  @BeforeClass
  public static void setUp() throws Exception {
    authorizer = new RangerAuthorizer();
    authorizer.initialize(new InMemoryAuthorizationContext());
  }


  /**
   * Ali has ADMIN on stream:testStream
   * rsinha has ADMIN on namespace:defaultNS
   * Shankar has ADMIN on programs:default.app1.*
   * Sagar has Admin on stream:default:*
   */
  @Test
  public void test() throws Exception {
    // ali should have admin on the teststream
    authorizer.enforce(new NamespaceId("default").stream("teststream"),
                       new Principal("ali", Principal.PrincipalType.USER), Action.ADMIN);

    // ali should not have admin on default ns
    testUnauthorized(new NamespaceId("default"),
                     new Principal("ali", Principal.PrincipalType.USER), Action.ADMIN);

    // rsinha should have admin on default namespace
    authorizer.enforce(new NamespaceId("default"),
                       new Principal("rsinha", Principal.PrincipalType.USER), Action.ADMIN);
    // rsinha should not have admin on the stream or application or program
    testUnauthorized(new NamespaceId("default").stream("teststream"),
                     new Principal("rsinha", Principal.PrincipalType.USER), Action.ADMIN);

    testUnauthorized(new NamespaceId("default").app("someapp"),
                     new Principal("rsinha", Principal.PrincipalType.USER), Action.ADMIN);
    testUnauthorized(new NamespaceId("default").app("someapp").program(ProgramType.MAPREDUCE, "someprog"),
                     new Principal("rsinha", Principal.PrincipalType.USER), Action.ADMIN);

    // shankar should not be able to access the stream
    testUnauthorized(new NamespaceId("default").stream("teststream"),
                     new Principal("shankar", Principal.PrincipalType.USER), Action.ADMIN);

    // shankar should be able to access program in app1 of default namespace but not the default ns itself
    testUnauthorized(new NamespaceId("default"),
                     new Principal("shankar", Principal.PrincipalType.USER), Action.ADMIN);
    authorizer.enforce(new NamespaceId("default").app("app1"),
                       new Principal("shankar", Principal.PrincipalType.USER), Action.ADMIN);
    authorizer.enforce(new NamespaceId("default").app("app1").program(ProgramType.MAPREDUCE, "someprog"),
                       new Principal("shankar", Principal.PrincipalType.USER), Action.ADMIN);

    // sagar should be able to access teststream
    authorizer.enforce(new NamespaceId("default").stream("teststream"),
                       new Principal("sagar", Principal.PrincipalType.USER), Action.ADMIN);
    // sagar should not be able to access app1
    testUnauthorized(new NamespaceId("default").app("app1"),

                     new Principal("sagar", Principal.PrincipalType.USER), Action.ADMIN);
    // sagar should not be able to default ns and he has only ADMIN on all streams and not the ns itself
    testUnauthorized(new NamespaceId("default"),
                     new Principal("sagar", Principal.PrincipalType.USER), Action.ADMIN);
  }

  private void testUnauthorized(EntityId entityId, Principal principal, Action action) throws Exception {
    try {
      authorizer.enforce(entityId, principal, action);
      Assert.fail(String.format("Principal %s, should be unauthorized for %s on entity %s", entityId, principal,
                                action));
    } catch (UnauthorizedException e) {
      // expected
    }
  }
}
