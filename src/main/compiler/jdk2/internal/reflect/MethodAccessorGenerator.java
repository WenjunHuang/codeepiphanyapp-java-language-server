/*
 * Copyright (c) 2001, 2018, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package jdk2.internal.reflect;

import java.security.AccessController;
import java.security.PrivilegedAction;

/** Generator for sun2.reflect.MethodAccessor and
    sun2.reflect.ConstructorAccessor objects using bytecodes to
    implement reflection. A java.lang.reflect.Method or
    java.lang.reflect.Constructor object can delegate its invoke or
    newInstance method to an accessor using native code or to one
    generated by this class. (Methods and Constructors were merged
    together in this class to ensure maximum code sharing.) */

class MethodAccessorGenerator extends AccessorGenerator {

    private static final short NUM_BASE_CPOOL_ENTRIES   = (short) 12;
    // One for invoke() plus one for constructor
    private static final short NUM_METHODS              = (short) 2;
    // Only used if forSerialization is true
    private static final short NUM_SERIALIZATION_CPOOL_ENTRIES = (short) 2;

    private static volatile int methodSymnum;
    private static volatile int constructorSymnum;
    private static volatile int serializationConstructorSymnum;

    private Class<?>   declaringClass;
    private Class<?>[] parameterTypes;
    private Class<?>   returnType;
    private boolean    isConstructor;
    private boolean    forSerialization;

    private short targetMethodRef;
    private short invokeIdx;
    private short invokeDescriptorIdx;
    // Constant pool index of CONSTANT_Class_info for first
    // non-primitive parameter type. Should be incremented by 2.
    private short nonPrimitiveParametersBaseIdx;

    MethodAccessorGenerator() {
    }

    /** This routine is not thread-safe */
    public MethodAccessor generateMethod(Class<?> declaringClass,
                                         String   name,
                                         Class<?>[] parameterTypes,
                                         Class<?>   returnType,
                                         Class<?>[] checkedExceptions,
                                         int modifiers)
    {
        return (MethodAccessor) generate(declaringClass,
                                         name,
                                         parameterTypes,
                                         returnType,
                                         checkedExceptions,
                                         modifiers,
                                         false,
                                         false,
                                         null);
    }

    /** This routine is not thread-safe */
    public ConstructorAccessor generateConstructor(Class<?> declaringClass,
                                                   Class<?>[] parameterTypes,
                                                   Class<?>[] checkedExceptions,
                                                   int modifiers)
    {
        return (ConstructorAccessor) generate(declaringClass,
                                              "<init>",
                                              parameterTypes,
                                              Void.TYPE,
                                              checkedExceptions,
                                              modifiers,
                                              true,
                                              false,
                                              null);
    }

    /** This routine is not thread-safe */
    public SerializationConstructorAccessorImpl
    generateSerializationConstructor(Class<?> declaringClass,
                                     Class<?>[] parameterTypes,
                                     Class<?>[] checkedExceptions,
                                     int modifiers,
                                     Class<?> targetConstructorClass)
    {
        return (SerializationConstructorAccessorImpl)
            generate(declaringClass,
                     "<init>",
                     parameterTypes,
                     Void.TYPE,
                     checkedExceptions,
                     modifiers,
                     true,
                     true,
                     targetConstructorClass);
    }

    /** This routine is not thread-safe */
    private MagicAccessorImpl generate(final Class<?> declaringClass,
                                       String name,
                                       Class<?>[] parameterTypes,
                                       Class<?>   returnType,
                                       Class<?>[] checkedExceptions,
                                       int modifiers,
                                       boolean isConstructor,
                                       boolean forSerialization,
                                       Class<?> serializationTargetClass)
    {
        ByteVector vec = ByteVectorFactory.create();
        asm = new ClassFileAssembler(vec);
        this.declaringClass = declaringClass;
        this.parameterTypes = parameterTypes;
        this.returnType = returnType;
        this.modifiers = modifiers;
        this.isConstructor = isConstructor;
        this.forSerialization = forSerialization;

        asm.emitMagicAndVersion();

        // Constant pool entries:
        // ( * = Boxing information: optional)
        // (+  = Shared entries provided by AccessorGenerator)
        // (^  = Only present if generating SerializationConstructorAccessor)
        //     [UTF-8] [This class's name]
        //     [CONSTANT_Class_info] for above
        //     [UTF-8] "jdk/internal/reflect/{MethodAccessorImpl,ConstructorAccessorImpl,SerializationConstructorAccessorImpl}"
        //     [CONSTANT_Class_info] for above
        //     [UTF-8] [Target class's name]
        //     [CONSTANT_Class_info] for above
        // ^   [UTF-8] [Serialization: Class's name in which to invoke constructor]
        // ^   [CONSTANT_Class_info] for above
        //     [UTF-8] target method or constructor name
        //     [UTF-8] target method or constructor signature
        //     [CONSTANT_NameAndType_info] for above
        //     [CONSTANT_Methodref_info or CONSTANT_InterfaceMethodref_info] for target method
        //     [UTF-8] "invoke" or "newInstance"
        //     [UTF-8] invoke or newInstance descriptor
        //     [UTF-8] descriptor for type of non-primitive parameter 1
        //     [CONSTANT_Class_info] for type of non-primitive parameter 1
        //     ...
        //     [UTF-8] descriptor for type of non-primitive parameter n
        //     [CONSTANT_Class_info] for type of non-primitive parameter n
        // +   [UTF-8] "java/lang/Exception"
        // +   [CONSTANT_Class_info] for above
        // +   [UTF-8] "java/lang/ClassCastException"
        // +   [CONSTANT_Class_info] for above
        // +   [UTF-8] "java/lang/NullPointerException"
        // +   [CONSTANT_Class_info] for above
        // +   [UTF-8] "java/lang/IllegalArgumentException"
        // +   [CONSTANT_Class_info] for above
        // +   [UTF-8] "java/lang/InvocationTargetException"
        // +   [CONSTANT_Class_info] for above
        // +   [UTF-8] "<init>"
        // +   [UTF-8] "()V"
        // +   [CONSTANT_NameAndType_info] for above
        // +   [CONSTANT_Methodref_info] for NullPointerException's constructor
        // +   [CONSTANT_Methodref_info] for IllegalArgumentException's constructor
        // +   [UTF-8] "(Ljava/lang/String;)V"
        // +   [CONSTANT_NameAndType_info] for "<init>(Ljava/lang/String;)V"
        // +   [CONSTANT_Methodref_info] for IllegalArgumentException's constructor taking a String
        // +   [UTF-8] "(Ljava/lang/Throwable;)V"
        // +   [CONSTANT_NameAndType_info] for "<init>(Ljava/lang/Throwable;)V"
        // +   [CONSTANT_Methodref_info] for InvocationTargetException's constructor
        // +   [CONSTANT_Methodref_info] for "super()"
        // +   [UTF-8] "java/lang/Object"
        // +   [CONSTANT_Class_info] for above
        // +   [UTF-8] "toString"
        // +   [UTF-8] "()Ljava/lang/String;"
        // +   [CONSTANT_NameAndType_info] for "toString()Ljava/lang/String;"
        // +   [CONSTANT_Methodref_info] for Object's toString method
        // +   [UTF-8] "Code"
        // +   [UTF-8] "Exceptions"
        //  *  [UTF-8] "java/lang/Boolean"
        //  *  [CONSTANT_Class_info] for above
        //  *  [UTF-8] "(Z)V"
        //  *  [CONSTANT_NameAndType_info] for above
        //  *  [CONSTANT_Methodref_info] for above
        //  *  [UTF-8] "booleanValue"
        //  *  [UTF-8] "()Z"
        //  *  [CONSTANT_NameAndType_info] for above
        //  *  [CONSTANT_Methodref_info] for above
        //  *  [UTF-8] "java/lang/Byte"
        //  *  [CONSTANT_Class_info] for above
        //  *  [UTF-8] "(B)V"
        //  *  [CONSTANT_NameAndType_info] for above
        //  *  [CONSTANT_Methodref_info] for above
        //  *  [UTF-8] "byteValue"
        //  *  [UTF-8] "()B"
        //  *  [CONSTANT_NameAndType_info] for above
        //  *  [CONSTANT_Methodref_info] for above
        //  *  [UTF-8] "java/lang/Character"
        //  *  [CONSTANT_Class_info] for above
        //  *  [UTF-8] "(C)V"
        //  *  [CONSTANT_NameAndType_info] for above
        //  *  [CONSTANT_Methodref_info] for above
        //  *  [UTF-8] "charValue"
        //  *  [UTF-8] "()C"
        //  *  [CONSTANT_NameAndType_info] for above
        //  *  [CONSTANT_Methodref_info] for above
        //  *  [UTF-8] "java/lang/Double"
        //  *  [CONSTANT_Class_info] for above
        //  *  [UTF-8] "(D)V"
        //  *  [CONSTANT_NameAndType_info] for above
        //  *  [CONSTANT_Methodref_info] for above
        //  *  [UTF-8] "doubleValue"
        //  *  [UTF-8] "()D"
        //  *  [CONSTANT_NameAndType_info] for above
        //  *  [CONSTANT_Methodref_info] for above
        //  *  [UTF-8] "java/lang/Float"
        //  *  [CONSTANT_Class_info] for above
        //  *  [UTF-8] "(F)V"
        //  *  [CONSTANT_NameAndType_info] for above
        //  *  [CONSTANT_Methodref_info] for above
        //  *  [UTF-8] "floatValue"
        //  *  [UTF-8] "()F"
        //  *  [CONSTANT_NameAndType_info] for above
        //  *  [CONSTANT_Methodref_info] for above
        //  *  [UTF-8] "java/lang/Integer"
        //  *  [CONSTANT_Class_info] for above
        //  *  [UTF-8] "(I)V"
        //  *  [CONSTANT_NameAndType_info] for above
        //  *  [CONSTANT_Methodref_info] for above
        //  *  [UTF-8] "intValue"
        //  *  [UTF-8] "()I"
        //  *  [CONSTANT_NameAndType_info] for above
        //  *  [CONSTANT_Methodref_info] for above
        //  *  [UTF-8] "java/lang/Long"
        //  *  [CONSTANT_Class_info] for above
        //  *  [UTF-8] "(J)V"
        //  *  [CONSTANT_NameAndType_info] for above
        //  *  [CONSTANT_Methodref_info] for above
        //  *  [UTF-8] "longValue"
        //  *  [UTF-8] "()J"
        //  *  [CONSTANT_NameAndType_info] for above
        //  *  [CONSTANT_Methodref_info] for above
        //  *  [UTF-8] "java/lang/Short"
        //  *  [CONSTANT_Class_info] for above
        //  *  [UTF-8] "(S)V"
        //  *  [CONSTANT_NameAndType_info] for above
        //  *  [CONSTANT_Methodref_info] for above
        //  *  [UTF-8] "shortValue"
        //  *  [UTF-8] "()S"
        //  *  [CONSTANT_NameAndType_info] for above
        //  *  [CONSTANT_Methodref_info] for above

        short numCPEntries = NUM_BASE_CPOOL_ENTRIES + NUM_COMMON_CPOOL_ENTRIES;
        boolean usesPrimitives = usesPrimitiveTypes();
        if (usesPrimitives) {
            numCPEntries += NUM_BOXING_CPOOL_ENTRIES;
        }
        if (forSerialization) {
            numCPEntries += NUM_SERIALIZATION_CPOOL_ENTRIES;
        }

        // Add in variable-length number of entries to be able to describe
        // non-primitive parameter types and checked exceptions.
        numCPEntries += (short) (2 * numNonPrimitiveParameterTypes());

        asm.emitShort(add(numCPEntries, S1));

        final String generatedName = generateName(isConstructor, forSerialization);
        asm.emitConstantPoolUTF8(generatedName);
        asm.emitConstantPoolClass(asm.cpi());
        thisClass = asm.cpi();
        if (isConstructor) {
            if (forSerialization) {
                asm.emitConstantPoolUTF8
                    ("jdk/internal/reflect/SerializationConstructorAccessorImpl");
            } else {
                asm.emitConstantPoolUTF8("jdk/internal/reflect/ConstructorAccessorImpl");
            }
        } else {
            asm.emitConstantPoolUTF8("jdk/internal/reflect/MethodAccessorImpl");
        }
        asm.emitConstantPoolClass(asm.cpi());
        superClass = asm.cpi();
        asm.emitConstantPoolUTF8(getClassName(declaringClass, false));
        asm.emitConstantPoolClass(asm.cpi());
        targetClass = asm.cpi();
        short serializationTargetClassIdx = (short) 0;
        if (forSerialization) {
            asm.emitConstantPoolUTF8(getClassName(serializationTargetClass, false));
            asm.emitConstantPoolClass(asm.cpi());
            serializationTargetClassIdx = asm.cpi();
        }
        asm.emitConstantPoolUTF8(name);
        asm.emitConstantPoolUTF8(buildInternalSignature());
        asm.emitConstantPoolNameAndType(sub(asm.cpi(), S1), asm.cpi());
        if (isInterface()) {
            asm.emitConstantPoolInterfaceMethodref(targetClass, asm.cpi());
        } else {
            if (forSerialization) {
                asm.emitConstantPoolMethodref(serializationTargetClassIdx, asm.cpi());
            } else {
                asm.emitConstantPoolMethodref(targetClass, asm.cpi());
            }
        }
        targetMethodRef = asm.cpi();
        if (isConstructor) {
            asm.emitConstantPoolUTF8("newInstance");
        } else {
            asm.emitConstantPoolUTF8("invoke");
        }
        invokeIdx = asm.cpi();
        if (isConstructor) {
            asm.emitConstantPoolUTF8("([Ljava/lang/Object;)Ljava/lang/Object;");
        } else {
            asm.emitConstantPoolUTF8
                ("(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
        }
        invokeDescriptorIdx = asm.cpi();

        // Output class information for non-primitive parameter types
        nonPrimitiveParametersBaseIdx = add(asm.cpi(), S2);
        for (int i = 0; i < parameterTypes.length; i++) {
            Class<?> c = parameterTypes[i];
            if (!isPrimitive(c)) {
                asm.emitConstantPoolUTF8(getClassName(c, false));
                asm.emitConstantPoolClass(asm.cpi());
            }
        }

        // Entries common to FieldAccessor, MethodAccessor and ConstructorAccessor
        emitCommonConstantPoolEntries();

        // Boxing entries
        if (usesPrimitives) {
            emitBoxingContantPoolEntries();
        }

        if (asm.cpi() != numCPEntries) {
            throw new InternalError("Adjust this code (cpi = " + asm.cpi() +
                                    ", numCPEntries = " + numCPEntries + ")");
        }

        // Access flags
        asm.emitShort(ACC_PUBLIC);

        // This class
        asm.emitShort(thisClass);

        // Superclass
        asm.emitShort(superClass);

        // Interfaces count and interfaces
        asm.emitShort(S0);

        // Fields count and fields
        asm.emitShort(S0);

        // Methods count and methods
        asm.emitShort(NUM_METHODS);

        emitConstructor();
        emitInvoke();

        // Additional attributes (none)
        asm.emitShort(S0);

        // Load class
        vec.trim();
        final byte[] bytes = vec.getData();
        // Note: the class loader is the only thing that really matters
        // here -- it's important to get the generated code into the
        // same namespace as the target class. Since the generated code
        // is privileged anyway, the protection domain probably doesn't
        // matter.
        return AccessController.doPrivileged(
            new PrivilegedAction<MagicAccessorImpl>() {
                @SuppressWarnings("deprecation") // Class.newInstance
                public MagicAccessorImpl run() {
                        try {
                        return (MagicAccessorImpl)
                        ClassDefiner.defineClass
                                (generatedName,
                                 bytes,
                                 0,
                                 bytes.length,
                                 declaringClass.getClassLoader()).newInstance();
                        } catch (InstantiationException | IllegalAccessException e) {
                            throw new InternalError(e);
                        }
                    }
                });
    }

    /** This emits the code for either invoke() or newInstance() */
    private void emitInvoke() {
        // NOTE that this code will only handle 65535 parameters since we
        // use the sipush instruction to get the array index on the
        // operand stack.
        if (parameterTypes.length > 65535) {
            throw new InternalError("Can't handle more than 65535 parameters");
        }

        // Generate code into fresh code buffer
        ClassFileAssembler cb = new ClassFileAssembler();
        if (isConstructor) {
            // 1 incoming argument
            cb.setMaxLocals(2);
        } else {
            // 2 incoming arguments
            cb.setMaxLocals(3);
        }

        short illegalArgStartPC = 0;

        if (isConstructor) {
            // Instantiate target class before continuing
            // new <target class type>
            // dup
            cb.opc_new(targetClass);
            cb.opc_dup();
        } else {
            // Get target object on operand stack if necessary.

            // We need to do an explicit null check here; we won't see
            // NullPointerExceptions from the invoke bytecode, since it's
            // covered by an exception handler.
            if (!isStatic()) {
                // aload_1
                // ifnonnull <checkcast label>
                // new <NullPointerException>
                // dup
                // invokespecial <NullPointerException ctor>
                // athrow
                // <checkcast label:>
                // aload_1
                // checkcast <target class's type>
                cb.opc_aload_1();
                Label l = new Label();
                cb.opc_ifnonnull(l);
                cb.opc_new(nullPointerClass);
                cb.opc_dup();
                cb.opc_invokespecial(nullPointerCtorIdx, 0, 0);
                cb.opc_athrow();
                l.bind();
                illegalArgStartPC = cb.getLength();
                cb.opc_aload_1();
                cb.opc_checkcast(targetClass);
            }
        }

        // Have to check length of incoming array and throw
        // IllegalArgumentException if not correct. A concession to the
        // JCK (isn't clearly specified in the spec): we allow null in the
        // case where the argument list is zero length.
        // if no-arg:
        //   aload_2 | aload_1 (Method | Constructor)
        //   ifnull <success label>
        // aload_2 | aload_1
        // arraylength
        // sipush <num parameter types>
        // if_icmpeq <success label>
        // new <IllegalArgumentException>
        // dup
        // invokespecial <IllegalArgumentException ctor>
        // athrow
        // <success label:>
        Label successLabel = new Label();
        if (parameterTypes.length == 0) {
            if (isConstructor) {
                cb.opc_aload_1();
            } else {
                cb.opc_aload_2();
            }
            cb.opc_ifnull(successLabel);
        }
        if (isConstructor) {
            cb.opc_aload_1();
        } else {
            cb.opc_aload_2();
        }
        cb.opc_arraylength();
        cb.opc_sipush((short) parameterTypes.length);
        cb.opc_if_icmpeq(successLabel);
        cb.opc_new(illegalArgumentClass);
        cb.opc_dup();
        cb.opc_invokespecial(illegalArgumentCtorIdx, 0, 0);
        cb.opc_athrow();
        successLabel.bind();

        // Iterate through incoming actual parameters, ensuring that each
        // is compatible with the formal parameter type, and pushing the
        // actual on the operand stack (unboxing and widening if necessary).

        short paramTypeCPIdx = nonPrimitiveParametersBaseIdx;
        Label nextParamLabel = null;
        byte count = 1; // both invokeinterface opcode's "count" as well as
        // num args of other invoke bytecodes
        for (int i = 0; i < parameterTypes.length; i++) {
            Class<?> paramType = parameterTypes[i];
            count += (byte) typeSizeInStackSlots(paramType);
            if (nextParamLabel != null) {
                nextParamLabel.bind();
                nextParamLabel = null;
            }
            // aload_2 | aload_1
            // sipush <index>
            // aaload
            if (isConstructor) {
                cb.opc_aload_1();
            } else {
                cb.opc_aload_2();
            }
            cb.opc_sipush((short) i);
            cb.opc_aaload();
            if (isPrimitive(paramType)) {
                // Unboxing code.
                // Put parameter into temporary local variable
                // astore_3 | astore_2
                if (isConstructor) {
                    cb.opc_astore_2();
                } else {
                    cb.opc_astore_3();
                }

                // repeat for all possible widening conversions:
                //   aload_3 | aload_2
                //   instanceof <primitive boxing type>
                //   ifeq <next unboxing label>
                //   aload_3 | aload_2
                //   checkcast <primitive boxing type> // Note: this is "redundant",
                //                                     // but necessary for the verifier
                //   invokevirtual <unboxing method>
                //   <widening conversion bytecode, if necessary>
                //   goto <next parameter label>
                // <next unboxing label:> ...
                // last unboxing label:
                //   new <IllegalArgumentException>
                //   dup
                //   invokespecial <IllegalArgumentException ctor>
                //   athrow

                Label l = null; // unboxing label
                nextParamLabel = new Label();

                for (int j = 0; j < primitiveTypes.length; j++) {
                    Class<?> c = primitiveTypes[j];
                    if (canWidenTo(c, paramType)) {
                        if (l != null) {
                            l.bind();
                        }
                        // Emit checking and unboxing code for this type
                        if (isConstructor) {
                            cb.opc_aload_2();
                        } else {
                            cb.opc_aload_3();
                        }
                        cb.opc_instanceof(indexForPrimitiveType(c));
                        l = new Label();
                        cb.opc_ifeq(l);
                        if (isConstructor) {
                            cb.opc_aload_2();
                        } else {
                            cb.opc_aload_3();
                        }
                        cb.opc_checkcast(indexForPrimitiveType(c));
                        cb.opc_invokevirtual(unboxingMethodForPrimitiveType(c),
                                             0,
                                             typeSizeInStackSlots(c));
                        emitWideningBytecodeForPrimitiveConversion(cb,
                                                                   c,
                                                                   paramType);
                        cb.opc_goto(nextParamLabel);
                    }
                }

                if (l == null) {
                    throw new InternalError
                        ("Must have found at least identity conversion");
                }

                // Fell through; given object is null or invalid. According to
                // the spec, we can throw IllegalArgumentException for both of
                // these cases.

                l.bind();
                cb.opc_new(illegalArgumentClass);
                cb.opc_dup();
                cb.opc_invokespecial(illegalArgumentCtorIdx, 0, 0);
                cb.opc_athrow();
            } else {
                // Emit appropriate checkcast
                cb.opc_checkcast(paramTypeCPIdx);
                paramTypeCPIdx = add(paramTypeCPIdx, S2);
                // Fall through to next argument
            }
        }
        // Bind last goto if present
        if (nextParamLabel != null) {
            nextParamLabel.bind();
        }

        short invokeStartPC = cb.getLength();

        // OK, ready to perform the invocation.
        if (isConstructor) {
            cb.opc_invokespecial(targetMethodRef, count, 0);
        } else {
            if (isStatic()) {
                cb.opc_invokestatic(targetMethodRef,
                                    count,
                                    typeSizeInStackSlots(returnType));
            } else {
                if (isInterface()) {
                    cb.opc_invokeinterface(targetMethodRef,
                                           count,
                                           count,
                                           typeSizeInStackSlots(returnType));
                } else {
                    cb.opc_invokevirtual(targetMethodRef,
                                         count,
                                         typeSizeInStackSlots(returnType));
                }
            }
        }

        short invokeEndPC = cb.getLength();

        if (!isConstructor) {
            // Box return value if necessary
            if (isPrimitive(returnType)) {
                cb.opc_invokestatic(boxingMethodForPrimitiveType(returnType),
                                    typeSizeInStackSlots(returnType),
                                    0);
            } else if (returnType == Void.TYPE) {
                cb.opc_aconst_null();
            }
        }
        cb.opc_areturn();

        // We generate two exception handlers; one which is responsible
        // for catching ClassCastException and NullPointerException and
        // throwing IllegalArgumentException, and the other which catches
        // all java/lang/Throwable objects thrown from the target method
        // and wraps them in InvocationTargetExceptions.

        short classCastHandler = cb.getLength();

        // ClassCast, etc. exception handler
        cb.setStack(1);
        cb.opc_invokespecial(toStringIdx, 0, 1);
        cb.opc_new(illegalArgumentClass);
        cb.opc_dup_x1();
        cb.opc_swap();
        cb.opc_invokespecial(illegalArgumentStringCtorIdx, 1, 0);
        cb.opc_athrow();

        short invocationTargetHandler = cb.getLength();

        // InvocationTargetException exception handler
        cb.setStack(1);
        cb.opc_new(invocationTargetClass);
        cb.opc_dup_x1();
        cb.opc_swap();
        cb.opc_invokespecial(invocationTargetCtorIdx, 1, 0);
        cb.opc_athrow();

        // Generate exception table. We cover the entire code sequence
        // with an exception handler which catches ClassCastException and
        // converts it into an IllegalArgumentException.

        ClassFileAssembler exc = new ClassFileAssembler();

        exc.emitShort(illegalArgStartPC);       // start PC
        exc.emitShort(invokeStartPC);           // end PC
        exc.emitShort(classCastHandler);        // handler PC
        exc.emitShort(classCastClass);          // catch type

        exc.emitShort(illegalArgStartPC);       // start PC
        exc.emitShort(invokeStartPC);           // end PC
        exc.emitShort(classCastHandler);        // handler PC
        exc.emitShort(nullPointerClass);        // catch type

        exc.emitShort(invokeStartPC);           // start PC
        exc.emitShort(invokeEndPC);             // end PC
        exc.emitShort(invocationTargetHandler); // handler PC
        exc.emitShort(throwableClass);          // catch type

        emitMethod(invokeIdx, cb.getMaxLocals(), cb, exc,
                   new short[] { invocationTargetClass });
    }

    private boolean usesPrimitiveTypes() {
        // We need to emit boxing/unboxing constant pool information if
        // the method takes a primitive type for any of its parameters or
        // returns a primitive value (except void)
        if (returnType.isPrimitive()) {
            return true;
        }
        for (int i = 0; i < parameterTypes.length; i++) {
            if (parameterTypes[i].isPrimitive()) {
                return true;
            }
        }
        return false;
    }

    private int numNonPrimitiveParameterTypes() {
        int num = 0;
        for (int i = 0; i < parameterTypes.length; i++) {
            if (!parameterTypes[i].isPrimitive()) {
                ++num;
            }
        }
        return num;
    }

    private boolean isInterface() {
        return declaringClass.isInterface();
    }

    private String buildInternalSignature() {
        StringBuilder sb = new StringBuilder();
        sb.append("(");
        for (int i = 0; i < parameterTypes.length; i++) {
            sb.append(getClassName(parameterTypes[i], true));
        }
        sb.append(")");
        sb.append(getClassName(returnType, true));
        return sb.toString();
    }

    private static synchronized String generateName(boolean isConstructor,
                                                    boolean forSerialization)
    {
        if (isConstructor) {
            if (forSerialization) {
                int num = ++serializationConstructorSymnum;
                return "jdk/internal/reflect/GeneratedSerializationConstructorAccessor" + num;
            } else {
                int num = ++constructorSymnum;
                return "jdk/internal/reflect/GeneratedConstructorAccessor" + num;
            }
        } else {
            int num = ++methodSymnum;
            return "jdk/internal/reflect/GeneratedMethodAccessor" + num;
        }
    }
}
