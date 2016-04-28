/*
 * Copyright 2016 Cask Data, Inc.
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

package co.cask.cdap.security.authorization.sentry.model;

import co.cask.cdap.proto.ProgramType;
import com.google.common.base.Preconditions;

import java.util.Objects;

/**
 * Represents the {@link Authorizable.AuthorizableType#PROGRAM} authorizable in CDAP
 */
public class Program implements Authorizable {
  private static final String PROGRAM_DETAILS_SEPARATOR = ".";

  private final ProgramType programType;
  private final String programName;

  /**
   * Create an {@link Authorizable.AuthorizableType#PROGRAM} authorizable of the given name.
   *
   * @param programDetails Details of the {@link Authorizable.AuthorizableType#PROGRAM} which should be in the
   * following format {@link ProgramType programType}.programName
   */
  public Program(String programDetails) {
    String splitter = "\\" + PROGRAM_DETAILS_SEPARATOR;
    String[] programTypeAndName = programDetails.trim().split(splitter, 2);
    Preconditions.checkArgument(
      programTypeAndName.length == 2, "Program details %s is invalid. Program details must be in the following " +
        "format: [program-type]%s[program-name].", programTypeAndName, PROGRAM_DETAILS_SEPARATOR);
    this.programType = ProgramType.valueOfPrettyName(programTypeAndName[0]);
    this.programName = programTypeAndName[1];
  }

  /**
   * Construct a {@link Program} from a known {@link ProgramType} and name
   *
   * @param programType the program type
   * @param programName the program name
   */
  public Program(ProgramType programType, String programName) {
    this.programType = programType;
    this.programName = programName;
  }

  /**
   * Get type of {@link Authorizable.AuthorizableType#PROGRAM} authorizable.
   *
   * @return Type of {@link Authorizable.AuthorizableType#PROGRAM} authorizable.
   */
  @Override
  public AuthorizableType getAuthzType() {
    return AuthorizableType.PROGRAM;
  }

  /**
   * Get program details of the {@link Authorizable.AuthorizableType#PROGRAM} in the following format
   * {@link ProgramType programType}.programName
   *
   * @return programType.programName of the {@link Authorizable.AuthorizableType#PROGRAM}.
   */
  @Override
  public String getName() {
    return programType + PROGRAM_DETAILS_SEPARATOR + programName;
  }

  /**
   * Get program type of the {@link Authorizable.AuthorizableType#PROGRAM}.
   *
   * @return program type of the {@link Authorizable.AuthorizableType#PROGRAM}.
   */
  public ProgramType getProgramType() {
    return programType;
  }

  /**
   * Get name of the {@link Authorizable.AuthorizableType#PROGRAM}.
   *
   * @return Name of the {@link Authorizable.AuthorizableType#PROGRAM}.
   */
  public String getProgramName() {
    return programName;
  }

  /**
   * Get type name of {@link Authorizable.AuthorizableType#PROGRAM}.
   *
   * @return Type name of {@link Authorizable.AuthorizableType#PROGRAM} authorizable.
   */
  @Override
  public String getTypeName() {
    return getAuthzType().name();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Program that = (Program) o;
    return Objects.equals(programName, that.programName) && Objects.equals(programType, that.programType);
  }

  @Override
  public int hashCode() {
    return Objects.hash(programName, programType);
  }
}
