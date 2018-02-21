from z3 import *
from itertools import product

# Parse 9x9 sudoku puzzle, dots are empty cells
sudoku = map(lambda line: list(line.strip()), """
.27.3....
1......7.
.83.7.24.
.71..5...
.3.....8.
...9..12.
.15.2.49.
.4......8
....1.56.
""".strip().split("\n"))


# Make 9x9 matrix for sudoku board
board = [[Int("board_%d_%d" %(x,y)) for y in range(9)] for x in range(9)]


# Create solver instance
solver = Solver()


# Add constraints from sudoku puzzle
for x, y in product(range(9), range(9)):
    if sudoku[x][y] != ".":
        solver.add(board[x][y] == int(sudoku[x][y]))


# Rules of sudoku:
#   1. All cells must have a number between 1 and 9.
#   2. All numbers in any row must be distinct.
#   3. All numbers in any column must be distinct. 
#   4. All numbers in 3x3 boxes must be distinct.
#   (5. All numbers in diagonals must contain be distinct)
# Hint: Have a look the "Distinct" constraint from z3


# ... add more constraints here to follow the rules for a sudoku ...


# check to see if this sudoku have a solution
assert solver.check() == sat


# print out solution(model) if one exists
model = solver.model()
for row in board:
    for cell in row:
        print model.eval(cell, model_completion=True),
    print 
