#!/usr/bin/env python3
# -*- coding: utf-8 -*-

''' Genetic Algorithm engine definition '''

import math
import time
import logging

from functools import wraps

# Imports for profiling.
import cProfile
import pstats
import os

from utils import settings

from .components import Individual, Population
from .plugin_interfaces.operators import Selection, Crossover, Mutation
from .plugin_interfaces.analysis import OnTheFlyAnalysis

def do_profile(filename, sortby='tottime'):
    '''
    Constructor for function profiling decorator.
    '''
    def _do_profile(func):
        '''
        Function profiling decorator.
        '''
        @wraps(func)
        def profiled_func(*args, **kwargs):
            '''
            Decorated function.
            '''
            # Flag for doing profiling or not.
            DO_PROF = os.getenv('PROFILING')

            if DO_PROF:
                profile = cProfile.Profile()
                profile.enable()
                result = func(*args, **kwargs)
                profile.disable()
                ps = pstats.Stats(profile).sort_stats(sortby)
                ps.dump_stats(filename)
            else:
                result = func(*args, **kwargs)
            return result
        return profiled_func

    return _do_profile


class StatVar(object):
    def __init__(self, name):
        '''
        Descriptor for statistical variables which need to be memoized when
        engine is running.
        '''
        # Protected.
        self.name = '_{}'.format(name)

    def __get__(self, engine, cls):
        '''
        Getter.
        '''
        stat_var = getattr(engine, self.name)
        if stat_var is None:
            if 'min' in self.name and 'ori' in self.name:
                stat_var = engine.population.min(engine.ori_fitness)
            elif 'min' in self.name:
                stat_var = engine.population.min(engine.fitness)
            elif 'max' in self.name and 'ori' in self.name:
                stat_var = engine.population.max(engine.ori_fitness)
            elif 'max' in self.name:
                stat_var = engine.population.max(engine.fitness)
            elif 'mean' in self.name and 'ori' in self.name:
                stat_var = engine.population.mean(engine.ori_fitness)
            elif 'mean' in self.name:
                stat_var = engine.population.mean(engine.fitness)
            setattr(engine, self.name, stat_var)
        return stat_var

    def __set__(self, engine, value):
        '''
        Setter.
        '''
        setattr(engine, self.name, value)


class EvolutionaryFuzzingEngine(object):
    # Statistical attributes for population.
    fmax, fmin, fmean = StatVar('fmax'), StatVar('fmin'), StatVar('fmean')
    ori_fmax, ori_fmin, ori_fmean = (StatVar('ori_fmax'),
                                     StatVar('ori_fmin'),
                                     StatVar('ori_fmean'))

    def __init__(self, population, selection, crossover, mutation, fitness=None, analysis=None, mapping=None):
        # Set logger.
        logger_name = 'engine.{}'.format(self.__class__.__name__)
        self.logger = logging.getLogger(logger_name)

        # Attributes assignment.
        self.population = population
        self.fitness = fitness
        self.selection = selection
        self.crossover = crossover
        self.mutation = mutation
        self.analysis = [] if analysis is None else [a() for a in analysis]
        self.mapping = mapping

        # Maxima and minima in population.
        self._fmax, self._fmin, self._fmean = None, None, None
        self._ori_fmax, self._ori_fmin, self._ori_fmean = None, None, None

        # Default fitness functions.
        self.ori_fitness = None if self.fitness is None else self.fitness

        # Store current generation number.
        self.current_generation = -1  # Starts from 0.

        # Check parameters validity.
        self._check_parameters()

    @do_profile(filename='engine_run.prof')
    def run(self, ng):
        '''
        Run the Genetic Algorithm optimization iteration with specified parameters.
        '''
        try:
            execution_begin = time.time()

            if self.fitness is None:
                raise AttributeError('No fitness function in GA engine')

            # Setup analysis objects.
            for a in self.analysis:
                a.setup(ng=ng, engine=self)
                a.register_step(g=-1, population=self.population, engine=self)

            # Enter evolution iteration.
            g = 0
            while g < ng or settings.GLOBAL_TIMEOUT:
                if settings.GLOBAL_TIMEOUT and time.time() - execution_begin >= settings.GLOBAL_TIMEOUT:
                    break

                self.current_generation = g

                indvs = []
                # NOTE: One series of genetic operation generates 2 new individuals.
                size = self.population.size // 2

                """for i in range(self.population.size):
                    individual = self.population.individuals[i].decode()
                    output = str(len(individual))
                    for input in individual:
                        tx = input["transaction"]
                        if tx["data"][:10] in self.mapping:
                            output += " " + self.mapping[tx["data"][:10]].split("(")[0] + "(" + tx["data"][11:] + ")"
                        else:
                            output += " " + tx["data"]
                    print(output)"""

                # Fill the new population.
                for _ in range(size):
                    # Select father and mother.
                    parents = self.selection.select(self.population, fitness=self.fitness)
                    # Crossover.
                    children = self.crossover.cross(*parents)
                    # Mutation.
                    children = [self.mutation.mutate(child, self) for child in children]
                    # Collect children.
                    indvs.extend(children)

                # The next generation.
                self.population.individuals = indvs

                # Run all analysis if needed.
                for a in self.analysis:
                    if g % a.interval == 0:
                        a.register_step(g=g, population=self.population, engine=self)

                g += 1
        except Exception as e:
            # Log exception info.
            msg = '{} exception is catched'.format(type(e).__name__)
            self.logger.exception(msg)
            raise e
        finally:
            # Perform the analysis post processing.
            for a in self.analysis:
                a.finalize(population=self.population, engine=self)

    def _update_statvars(self):
        '''
        Private helper function to update statistic variables in GA engine, like
        maximum, minimum and mean values.
        '''
        # Wrt original fitness.
        self.ori_fmax = self.population.max(self.ori_fitness)
        self.ori_fmin = self.population.min(self.ori_fitness)
        self.ori_fmean = self.population.mean(self.ori_fitness)

        # Wrt decorated fitness.
        self.fmax = self.population.max(self.fitness)
        self.fmin = self.population.min(self.fitness)
        self.fmean = self.population.mean(self.fitness)

    def _check_parameters(self):
        '''
        Helper function to check parameters of engine.
        '''
        if not isinstance(self.population, Population):
            raise TypeError('population must be a Population object')
        if not isinstance(self.selection, Selection):
            raise TypeError('selection operator must be a Selection instance')
        if not isinstance(self.crossover, Crossover):
            raise TypeError('crossover operator must be a Crossover instance')
        if not isinstance(self.mutation, Mutation):
            raise TypeError('mutation operator must be a Mutation instance')

        for ap in self.analysis:
            if not isinstance(ap, OnTheFlyAnalysis):
                msg = '{} is not subclass of OnTheFlyAnalysis'.format(ap.__name__)
                raise TypeError(msg)

    # Decorators.

    def fitness_register(self, fn):
        '''
        A decorator for fitness function register.
        '''
        @wraps(fn)
        def _fn_with_fitness_check(indv):
            '''
            A wrapper function for fitness function with fitness value check.
            '''
            # Check indv type.
            if not isinstance(indv, Individual):
                raise TypeError('indv\'s class must be Individual or a subclass of Individual')

            # Check fitness.
            fitness = fn(indv)
            is_invalid = (type(fitness) is not float) or (math.isnan(fitness))
            if is_invalid:
                msg = 'Fitness value(value: {}, type: {}) is invalid'
                msg = msg.format(fitness, type(fitness))
                raise ValueError(msg)
            return fitness

        self.fitness = _fn_with_fitness_check
        if self.ori_fitness is None:
            self.ori_fitness = _fn_with_fitness_check

    def analysis_register(self, analysis_cls):
        '''
        A decorator for analysis regsiter.
        '''
        if not issubclass(analysis_cls, OnTheFlyAnalysis):
            raise TypeError('analysis class must be subclass of OnTheFlyAnalysis')

        # Add analysis instance to engine.
        analysis = analysis_cls()
        self.analysis.append(analysis)

    # Functions for fitness scaling.

    def linear_scaling(self, target='max', ksi=0.5):
        '''
        A decorator constructor for fitness function linear scaling.

        :param target: The optimization target, maximization or minimization.
        :type target: str, 'max' or 'min'

        :param ksi: Selective pressure adjustment value.
        :type ksi: float

        Linear Scaling:
            1. arg max f(x), then f' = f - min{f(x)} + ksi;
            2. arg min f(x), then f' = max{f(x)} - f(x) + ksi;
        '''
        def _linear_scaling(fn):
            # For original fitness calculation.
            self.ori_fitness = fn

            @wraps(fn)
            def _fn_with_linear_scaling(indv):
                # Original fitness value.
                f = fn(indv)

                # Determine the value of a and b.
                if target == 'max':
                    f_prime = f - self.ori_fmin + ksi
                elif target == 'min':
                    f_prime = self.ori_fmax - f + ksi
                else:
                    raise ValueError('Invalid target type({})'.format(target))
                return f_prime

            return _fn_with_linear_scaling

        return _linear_scaling

    def dynamic_linear_scaling(self, target='max', ksi0=2, r=0.9):
        '''
        A decorator constructor for fitness dynamic linear scaling.

        :param target: The optimization target, maximization or minimization.
        :type target: str, 'max' or 'min'

        :param ksi0: Initial selective pressure adjustment value, default value
                     is 2
        :type ksi0: float

        :param r: The reduction factor for selective pressure adjustment value,
                  ksi^(k-1)*r is the adjustment value for generation k, default
                  value is 0.9
        :type r: float in range [0.9, 0.999]

        Dynamic Linear Scaling:
            For maximizaiton, f' = f(x) - min{f(x)} + ksi^k, k is generation number.
        '''
        def _dynamic_linear_scaling(fn):
            # For original fitness calculation.
            self.ori_fitness = fn

            @wraps(fn)
            def _fn_with_dynamic_linear_scaling(indv):
                f = fn(indv)
                k = self.current_generation + 1

                if target == 'max':
                    f_prime = f - self.ori_fmin + ksi0*(r**k)
                elif target == 'min':
                    f_prime = self.ori_fmax - f + ksi0*(r**k)
                else:
                    raise ValueError('Invalid target type({})'.format(target))
                return f_prime

            return _fn_with_dynamic_linear_scaling

        return _dynamic_linear_scaling

    def minimize(self, fn):
        '''
        A decorator for minimizing the fitness function.
        '''
        @wraps(fn)
        def _minimize(indv):
            return -fn(indv)
        return _minimize
