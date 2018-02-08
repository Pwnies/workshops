" Leaders
let mapleader = "\<space>"
let maplocalleader = "\<tab>"

" Set default clipboard
set clipboard=unnamedplus

" Better split switching
nnoremap <C-J> <C-W><C-J>
nnoremap <C-K> <C-W><C-K>
nnoremap <C-L> <C-W><C-L>
nnoremap <C-H> <C-W><C-H>

" You're doing it wrong
nnoremap <up> <nop>
nnoremap <down> <nop>
nnoremap <left> <nop>
nnoremap <right> <nop>
inoremap <up> <nop>
inoremap <down> <nop>
inoremap <left> <nop>
inoremap <right> <nop>
nnoremap j gj
nnoremap k gk

" Fucking ex mode
map q: <nop>
nnoremap Q <nop>

" Misc
filetype plugin indent on

syntax on

" Store swap files in fixed location
set dir=~/.vimswap//,/var/tmp//,/tmp//,.

" Look
let $NVIM_TUI_ENABLE_CURSOR_SHAPE = 1
set showcmd
set showmatch
set showmode
set number
set formatoptions+=o
set tabstop=4
set shiftwidth=4
set noerrorbells
set linespace=0
set relativenumber
set undofile

" Fix search and replace
nnoremap / /\v
vnoremap / /\v
set ignorecase
set smartcase
set gdefault
set incsearch
set showmatch
set hlsearch
:nnoremap <silent> <Space> :nohlsearch<Bar>:echo<CR>

" Move around bracets
nnoremap <tab> %
vnoremap <tab> %

" Disable help key
inoremap <F1> <ESC>
nnoremap <F1> <ESC>
vnoremap <F1> <ESC>

" Expand tabs
set expandtab
set tabstop=4
set shiftwidth=4
autocmd BufWritePre * :%s/\s\+$//e
if &listchars ==# 'eol:$'
  set listchars=tab:>\ ,trail:-,extends:>,precedes:<,nbsp:+
endif
set list

" Spell check
au BufReadPost,BufNewFile *.md,*.txt,*.tex set spell
