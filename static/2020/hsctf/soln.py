#!/usr/bin/env python3
from enum import Enum
import z3
import attr
import pdb
import sys

num_vars = 24

FLAG = "xB^r_En}INc4v"

# This is the true output of the actual flag
real_output = (120, 64, 94, 116, 190, 19, 160, 125, 73, 130, 99, 52, 118)

# This is the fake answer absolute tease: list(map(ord, "xB^r_En}INc4v"))
expected = (120, 66, 94, 114, 95, 69, 110, 125, 73, 78, 99, 52, 118)

# ['♈', '♉', '♊', '♋', '♌', '♍', '♎', '♏', '♐', '♑', '♒', '♓']
# sign_variables = [chr(i) for i in range(9800, 9812)]
sign_variables = [i for i in range(9800, 9812)]

# ['🕐', '🕑', '🕒', '🕓', '🕔', '🕕', '🕖', '🕗', '🕘', '🕙', '🕚', '🕛']
# time_variables = [chr(i) for i in range(128336, 128348)]
time_variables = [i for i in range(128336, 128348)]

variable_symbols = sign_variables + time_variables
variable_nums = dict(zip(variable_symbols, range(len(variable_symbols))))
variable_names = ["r{}".format(i) for i in range(len(variable_symbols))]

symbols_to_names = dict(zip(variable_symbols, variable_names))
pc_symbol = 128680  # 🚨

# 💔 💜 💕 💞 💖
constants = {128148: 0, 128156: 1, 128149: 2, 128158: 4, 128150: 8}


class IO(Enum):
    IN = 0
    OUT = 1


class Ops(Enum):
    MOV = 0  # [VAR] = VAL
    ADD = 1  # [VAR] = [VAR] + VAL
    SUB = 2  # [VAR] = [VAR] - VAL
    IFEQ = 3  # if [VAR] == VAL: pc += 2 (skip)


# 😊 😇 😈 😵
ops = {128522: Ops.MOV, 128519: Ops.ADD, 128520: Ops.SUB, 128565: Ops.IFEQ}
io = {127908: IO.IN, 128226: IO.OUT}


class Instruction:
    def __init__(self, op, var, val):
        self.op_num = op
        self.var_num = var
        self.val_num = val

        self.val = None
        self.var = None

    @classmethod
    def make_from_text(cls, insn):
        assert len(insn) == 3

        op_num, var_num, val_num = list(map(ord, insn))
        return cls(op_num, var_num, val_num)

    def disassemble(self):

        op = ops[self.op_num]
        var = None
        val = None

        if op == Ops.MOV:
            # Could be an IO operation?
            if self.var_num in io.keys():
                var = io[self.var_num].name

        if self.val_num in variable_symbols:
            val = symbols_to_names[self.val_num]
        elif self.val_num in constants:
            val = constants[self.val_num]
        elif self.val_num in io.keys():
            val = io[self.val_num].name
        else:
            print("Couldn't find: {}".format(self.val_num))
            assert False

        if var is None:
            var = symbols_to_names[self.var_num]

        return "{}\t{}\t{}".format(op.name, var, val)

    def doMov(self, state, var_num, val_num):
        if val_num in io.keys():
            # means we doing input
            inp = input("> ")
            state = state.setVar(var_num, ord(inp))

            return state.step()

        if var_num in io.keys():
            # means we doing output
            outVar = state.variables[val_num]
            state = state.pushOut(outVar)

            return state.step()

        # not doing IO stuff, yay!

        rhs = None

        if isVariable(val_num):
            rhs = state.variables[val_num]
        else:
            rhs = constants[val_num]

        return state.setVar(var_num, rhs).step()

    def doAdd(self, state, var_num, val_num):
        rhs = None

        if isVariable(val_num):
            rhs = state.variables[val_num]
        else:
            rhs = constants[val_num]

        lhs = state.variables[var_num]

        res = lhs + rhs
        return state.setVar(var_num, res).step()

    def doSub(self, state, var_num, val_num):
        rhs = None

        if isVariable(val_num):
            rhs = state.variables[val_num]
        else:
            rhs = constants[val_num]

        lhs = state.variables[var_num]

        res = lhs - rhs
        return state.setVar(var_num, res).step()

    def doIf(self, state, var_num, val_num):
        if isVariable(val_num):
            rhs = state.variables[val_num]
        else:
            rhs = constants[val_num]

        lhs = state.variables[var_num]

        if lhs == rhs:
            # skip next line
            return state.step().step()
        else:
            return state.step()

    def execute(self, state):
        op = ops[self.op_num]
        opFuns = {
            Ops.ADD: self.doAdd,
            Ops.SUB: self.doSub,
            Ops.MOV: self.doMov,
            Ops.IFEQ: self.doIf,
        }

        return opFuns[op](state, self.var_num, self.val_num)


@attr.s(frozen=True)
class Model:
    state = attr.ib()
    constraints = attr.ib()


@attr.s(frozen=True)
class State:
    """
    Immutable state object that gets handled by visiting functions
    """

    pc = attr.ib()
    variables = attr.ib()
    num_read = attr.ib()
    stdout = attr.ib()
    flag_in_vars = attr.ib()

    @classmethod
    def empty(cls):
        pc = 0
        variables = dict({var: 0 for var in variable_symbols})
        readIN = 0
        stdout = ()
        flag_in_vars = ()

        return cls(pc, variables, readIN, stdout, flag_in_vars)

    def step(self):
        return attr.evolve(self, pc=self.pc + 1)

    def readIn(self):
        """
        Simulate reading in a character from stdin
        """
        new_var = z3.Int("flag_in[{}]".format(self.num_read))
        return (
            attr.evolve(
                self,
                num_read=self.num_read + 1,
                flag_in_vars=self.flag_in_vars + (new_var,),
            ),
            new_var,
        )

    def pushOut(self, char):
        """Simulate pushing a character to stdout"""
        return attr.evolve(self, stdout=self.stdout + (char,))

    def setVar(self, var, value):
        new_dict = self.variables.copy()
        new_dict[var] = value
        return attr.evolve(self, variables=new_dict)


def isVariable(val):
    return val in variable_nums.keys()


def modelMov(state, var_num, val_num, constraints, _, insns):
    """
    Be careful this include IO ops which sucks
    """

    if val_num in io.keys():
        # means we doing input
        state, inSym = state.readIn()
        state = state.setVar(var_num, inSym)

        return symbolicVisit(state.step(), constraints, insns)

    if var_num in io.keys():
        # means we doing output
        outVar = state.variables[val_num]
        state = state.pushOut(outVar)

        return symbolicVisit(state.step(), constraints, insns)

    # not doing IO, yay

    rhs = None

    if isVariable(val_num):
        rhs = state.variables[val_num]
    else:
        rhs = constants[val_num]

    return symbolicVisit(state.setVar(var_num, rhs).step(), constraints, insns)


def modelAdd(state, var_num, val_num, constraints, _, insns):
    rhs = None

    if isVariable(val_num):
        rhs = state.variables[val_num]
    else:
        rhs = constants[val_num]

    lhs = state.variables[var_num]

    constraint = lhs + rhs
    return symbolicVisit(state.setVar(var_num, constraint).step(), constraints, insns)


def modelSub(state, var_num, val_num, constraints, _, insns):
    if isVariable(val_num):
        rhs = state.variables[val_num]
    else:
        rhs = constants[val_num]

    lhs = state.variables[var_num]

    constraint = lhs - rhs

    return symbolicVisit(state.setVar(var_num, constraint).step(), constraints, insns)


def modelIf(state, var_num, val_num, constraints, insn, insns):
    if isVariable(val_num):
        rhs = state.variables[val_num]
    else:
        rhs = constants[val_num]

    lhs = state.variables[var_num]

    true_constraint = lhs == rhs
    false_constraint = lhs != rhs

    # two steps to skip
    trueModels = symbolicVisit(
        state.step().step(), constraints + (true_constraint,), insns
    )
    falseModels = symbolicVisit(state.step(), constraints + (false_constraint,), insns)

    return trueModels + falseModels


funs = {128522: modelMov, 128519: modelAdd, 128520: modelSub, 128565: modelIf}


def stepModel(model):
    return attr.evolve(model, state=model.state.step())


def symbolicVisit(state, constraints, insns):
    """Recursive z3 constraint builder"""

    if state.pc == len(insns):
        # base case
        return (Model(state=state, constraints=constraints),)

    insn = insns[state.pc]
    op_num, var_num, val_num = list(map(ord, insn))

    return funs[op_num](state, var_num, val_num, constraints, insn, insns)


def disassemble(ops):
    print("ADDR    OPCODE\tLHS\tRHS\tORIGINAL")
    print("========================================")
    for addr, instruction in enumerate(ops):
        i = Instruction.make_from_text(instruction)
        print("{:03d}:    {}\t({})".format(addr, i.disassemble(), instruction))


def execute(state, insns):
    if state.pc == len(insns):
        # base case
        return state

    insn = insns[state.pc]
    i = Instruction.make_from_text(insn)

    next_state = i.execute(state)

    return execute(next_state, insns)


def solve(insns):

    state = State.empty()
    fin_states = symbolicVisit(state, (), insns)

    print("[*] number of states = {}".format(len(fin_states)))


    for i, fin in enumerate(fin_states):
        s = z3.Solver()
        state, constraints = fin.state, fin.constraints
        if i == 13:
            pdb.set_trace()

        for constraint in constraints:
            s.add(constraint)

        for input_var in state.flag_in_vars:
            s.add(input_var > 32)
            s.add(input_var < 128)

        if s.check() != z3.sat:
            continue

        for char, out in zip(real_output, state.stdout):
            s.add(out == char)

        if s.check() == z3.sat:
            print("[*] Got one!")
            m = s.model()

            for d in m.decls():
                print("{} = {}".format(d.name(), chr(m[d].as_long())))

            return
    print("[-] Output isn't possible :(")



if len(sys.argv) != 3:
    print("usage: ./{} <emoji_file> <emu|dis|sim>".format(sys.argv[0]))
    sys.exit(0)

filename = sys.argv[1]

insns = open(filename).readlines()
insns = list(map(lambda x: x.strip(), insns))

if sys.argv[2] == "emu":
    print("[*] Doing emulation:")
    e_state = State.empty()
    ef_state = execute(e_state, insns)

    try:
        print(
            "[*] got stdout of= '{}'".format("".join(tuple(map(chr, ef_state.stdout))))
        )
    except:
        print("[-] stdout not ascii...")

    print("[+] got stdout of: {}".format(ef_state.stdout))
elif sys.argv[2] == "dis":
    disassemble(insns)
elif sys.argv[2] == "sim":
    solve(insns)
else:
    print("usage: {} <emoji_file> <emu|dis|sim>")
