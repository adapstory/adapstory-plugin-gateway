package com.adapstory.gateway.architecture;

import static com.adapstory.starter.testing.archunit.RestControllerSecurityRules.allEndpointMethodsMustHaveSecurityAnnotation;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.fields;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.library.dependencies.SlicesRuleDefinition.slices;

import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import org.junit.jupiter.api.DisplayName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;

/**
 * Architecture rules for Plugin Gateway.
 *
 * <p>Validates BFF-specific structural constraints: package residency, dependency direction,
 * constructor injection limits, field injection ban, and endpoint security annotations. Additional
 * gateway-specific rules enforce DTO, event, and filter package containment.
 */
@DisplayName("BFF architecture rules for Plugin Gateway")
@AnalyzeClasses(
    packages = "com.adapstory.gateway",
    importOptions = ImportOption.DoNotIncludeTests.class)
class PluginGatewayArchitectureTest {

  private static final String BASE = "com.adapstory.gateway";

  // ── Shared starter rules ──────────────────────────────────────────────

  @ArchTest
  static final ArchRule all_endpoints_have_security_annotation =
      allEndpointMethodsMustHaveSecurityAnnotation(BASE);

  // ── No field injection ────────────────────────────────────────────────

  @ArchTest
  static final ArchRule no_field_injection =
      fields()
          .that()
          .areDeclaredInClassesThat()
          .resideInAPackage(BASE + "..")
          .should()
          .notBeAnnotatedWith(Autowired.class)
          .as("Fields must not use @Autowired — use constructor injection with final");

  // ── Constructor dependency limit (SRP-01) ─────────────────────────────

  @ArchTest
  static final ArchRule max_7_constructor_dependencies =
      classes()
          .that()
          .resideInAPackage(BASE + "..")
          .and()
          .areNotAnonymousClasses()
          .and()
          .areNotMemberClasses()
          .and()
          .areNotRecords()
          .should(haveAtMostNConstructorDependencies(7))
          .allowEmptyShould(true)
          .as("Classes must have max 7 constructor parameters — extract facade if needed (SRP-01)");

  // ── Package residency rules ───────────────────────────────────────────

  @ArchTest
  static final ArchRule config_classes_in_config_package =
      classes()
          .that()
          .areAnnotatedWith(Configuration.class)
          .and()
          .resideInAPackage(BASE + "..")
          .should()
          .resideInAPackage(BASE + ".config..")
          .allowEmptyShould(true)
          .as("@Configuration classes must reside in the config package");

  @ArchTest
  static final ArchRule filters_in_filter_package =
      classes()
          .that()
          .haveSimpleNameEndingWith("Filter")
          .and()
          .resideInAPackage(BASE + "..")
          .and()
          .areNotAnonymousClasses()
          .should()
          .resideInAPackage(BASE + ".filter..")
          .allowEmptyShould(true)
          .as("Filter classes must reside in the filter package");

  @ArchTest
  static final ArchRule dtos_in_dto_package =
      classes()
          .that()
          .resideInAPackage(BASE + "..")
          .and(haveDtoLikeName())
          .and()
          .areNotAnonymousClasses()
          .and()
          .areNotMemberClasses()
          .should()
          .resideInAPackage(BASE + ".dto..")
          .allowEmptyShould(true)
          .as("DTO/Response/Request classes must reside in the dto package");

  @ArchTest
  static final ArchRule events_in_event_package =
      classes()
          .that()
          .haveSimpleNameEndingWith("Event")
          .and()
          .resideInAPackage(BASE + "..")
          .and()
          .areNotAnonymousClasses()
          .should()
          .resideInAPackage(BASE + ".event..")
          .allowEmptyShould(true)
          .as("Event classes must reside in the event package");

  // ── Layer isolation ───────────────────────────────────────────────────

  @ArchTest
  static final ArchRule no_circular_dependencies_between_packages =
      slices()
          .matching(BASE + ".(*)..")
          .should()
          .beFreeOfCycles()
          .ignoreDependency(
              DescribedPredicate.describe(
                  "config package (Spring Security wiring)",
                  clazz -> clazz.getPackageName().startsWith(BASE + ".config")),
              DescribedPredicate.describe(
                  "filter package", clazz -> clazz.getPackageName().startsWith(BASE + ".filter")))
          .as("Packages under " + BASE + " must not have circular dependencies");

  @ArchTest
  static final ArchRule routing_does_not_depend_on_filter =
      noClasses()
          .that()
          .resideInAPackage(BASE + ".routing..")
          .should()
          .dependOnClassesThat()
          .resideInAPackage(BASE + ".filter..")
          .as("Routing must not depend on filter package — maintain layer isolation");

  // ── Custom predicates and conditions ──────────────────────────────────

  private static DescribedPredicate<JavaClass> haveDtoLikeName() {
    return DescribedPredicate.describe(
        "have a DTO-like name ending in Dto, DTO, Response, or Request",
        clazz -> {
          String name = clazz.getSimpleName();
          return (name.endsWith("Dto")
              || name.endsWith("DTO")
              || name.endsWith("Response")
              || name.endsWith("Request"));
        });
  }

  private static ArchCondition<JavaClass> haveAtMostNConstructorDependencies(int maxDeps) {
    return new ArchCondition<>("have at most " + maxDeps + " constructor dependencies") {
      @Override
      public void check(JavaClass javaClass, ConditionEvents events) {
        javaClass.getConstructors().stream()
            .filter(ctor -> ctor.getRawParameterTypes().size() > maxDeps)
            .forEach(
                ctor ->
                    events.add(
                        SimpleConditionEvent.violated(
                            javaClass,
                            javaClass.getName()
                                + " constructor has "
                                + ctor.getRawParameterTypes().size()
                                + " parameters (max "
                                + maxDeps
                                + ") — extract facade (SRP-01)")));
      }
    };
  }
}
